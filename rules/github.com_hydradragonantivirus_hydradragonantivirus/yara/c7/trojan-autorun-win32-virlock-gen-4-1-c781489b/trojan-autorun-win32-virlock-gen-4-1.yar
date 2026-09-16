rule Trojan_Autorun_Win32_Virlock_Gen_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Virlock.Gen.4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70a56997b06f31557033f95683f1ff1839585a049e87410fbd729a2c2e6b9f37"

  strings:
    $s1 = "*odAl$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}