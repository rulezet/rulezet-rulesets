rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a9990a4ff8eacd51f55e6a92fe8c1bad669a4fca24180e99c5e959ccb8e36b0"

  strings:
    $s1 = "*Unable to get a list of running processes. Unable to get the process token.Invalid element in a DllStruct.*Unknown option or b" wide
    $s2 = "AutoIt v3 Script: 3, 3, 8, 1" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}