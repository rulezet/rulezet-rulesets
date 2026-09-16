rule Trojan_Danger_Trojan_Generic_4385790_12_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.4385790_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7af59687f9fe396f99e4d48aa048947545306d06afd96b140c869364474286a"

  strings:
    $s1 = "6available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}