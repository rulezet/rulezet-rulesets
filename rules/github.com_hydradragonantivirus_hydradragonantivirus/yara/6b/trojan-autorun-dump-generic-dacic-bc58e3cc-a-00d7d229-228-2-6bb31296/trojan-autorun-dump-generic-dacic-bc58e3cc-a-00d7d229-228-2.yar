rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_228_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_228_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e74ed2209bc94f38ef5c90e655bbe8c34ddc0dd6b5c0b60ce14ee4f8aeac928a"

  strings:
    $s1 = "System.Net.WebSockets.WebSocketBase+WebSocketOperation+<Process>d__19" fullword ascii
    $s2 = "SELECT * FROM Win32_Process Where SessionId='{0}'" fullword wide
    $s3 = "HI! Write first number" fullword wide
    $s4 = "HI! Write second number" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}