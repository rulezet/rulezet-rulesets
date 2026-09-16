rule Trojan_Danger_Generic_Dacic_1A7FA519_A_F28017CC_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.F28017CC_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "861f6a350bac6dd91baed8f68ecb5817af06f4c26e347ee41038bac94cad817f"

  strings:
    $s1 = "?University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}