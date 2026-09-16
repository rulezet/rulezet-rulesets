rule Virus_Autorun_Win32_Neshta_A_33 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_33.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cf8eeda104f2cd0c8973326584a26ae9c5573aa5149a622a46ff566d648cd02"

  strings:
    $s1  = "Inno Setup Uninstall Log (b) 64-bitInvalid header IDHeader version not supportedCRC32 check failedFailed to read header to buffe" ascii
    $s2  = "stack not emptyC:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-6f17d22bba15001f\\slog-term-2.9.0\\src\\lib.rs" fullword ascii
    $s3  = "The logger thread terminatedP" fullword ascii
    $s4  = "attempt to divide by zero/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library\\core\\src\\str\\pattern.rs)" fullword ascii
    $s5  = "assertion failed: mid <= self.len()/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library\\core\\src\\escape.rs" fullword ascii
    $s6  = "cannot access a Thread Local Storage value during or after destruction/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library" ascii
    $s7  = "cannot access a Thread Local Storage value during or after destruction/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library" ascii
    $s8  = "internal error: entered unreachable code/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library\\alloc\\src\\vec\\mod.rsx" fullword ascii
    $s9  = "[[Simulated error message]]failed to fill buffersrc\\blockio.rs" fullword ascii
    $s10 = "Visual Studio Codesrc\\util.rs" fullword ascii
    $s11 = "Visual Studio Code is updating...src\\model\\filerec.rs" fullword ascii
    $s12 = "Could not convert from utf16x" fullword ascii
    $s13 = "range end index LPE" fullword ascii
    $s14 = " right: PNE" fullword ascii
    $s15 = "called `Option::unwrap()` on a `None` value/rustc/07dca489ac2d933c78d3c5158e3f43beefeb02ce\\library\\core\\src\\io\\borrowed_buf" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}