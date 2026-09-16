rule VirusShareTrojanInject316829_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject316829_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24ea81e04618ce6884bd241fa03f7dea6e8eed01d4c3e3dc2a5fd2410187b60d"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\" xmlns:v3=\"urn:schemas-microsoft-com:asm.v3\"><asse" ascii
    $s2  = "start(Mcode, TargetHost,bBuffer)" fullword ascii
    $s3  = "{Blind}%s%s{%s DownTemp}" fullword wide
    $s4  = "Could not open URL http://ahkscript.org in default browser." fullword wide
    $s5  = "Launch Error (possibly related to RunAs)." fullword wide
    $s6  = "start(ByRef ASM,ByRef Host ,ByRef Buff ) {" fullword ascii
    $s7  = "Loop, %l% {" fullword ascii
    $s8  = "; <COMPILER: v1.1.23.00>" fullword ascii
    $s9  = "DllCall(lib, \"Ptr\", &ASM, \"str\", Host, \"Ptr\", &Buff, \"Uint\", 0, \"Uint\", 0)" fullword ascii
    $s10 = "Return, s" fullword ascii
    $s11 = "main(){" fullword ascii
    $s12 = "Return Bytes" fullword ascii
    $s13 = "Random, r, i, x" fullword ascii
    $s14 = "%s[Object]: 0x%p" fullword wide
    $s15 = "Could not launch file:" fullword wide
    $s16 = "}catch {" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}