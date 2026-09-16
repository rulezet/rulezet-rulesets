rule sig_20160823_77e8bb6f6eed94a198028d1ab80335f3 {
  meta:
    description = "datamaliciousorder - file 20160823_77e8bb6f6eed94a198028d1ab80335f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949e44a6240bba9f92179120b762a38c349ee0a5c14e39874c77c282c2aba992"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}