rule Virus_Hijack_Trojan_GenericKDZ_103285_655_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_655_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53b3e3104ecf86b725095a2721c82364a0ebfe7ca830614b17250bb2f5a33a3e"

  strings:
    $s1 = "url.org/dc/elements/1.1/\" xmlns:photoshop=\"http://ns.adobe.com/photoshop/1.0/\" xmlns:xmpMM=\"http://ns.adobe.com/xap/1.0/mm/" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}