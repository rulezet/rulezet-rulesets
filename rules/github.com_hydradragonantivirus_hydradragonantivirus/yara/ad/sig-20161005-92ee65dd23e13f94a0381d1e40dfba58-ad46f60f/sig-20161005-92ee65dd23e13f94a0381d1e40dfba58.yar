rule sig_20161005_92ee65dd23e13f94a0381d1e40dfba58 {
  meta:
    description = "datamaliciousorder - file 20161005_92ee65dd23e13f94a0381d1e40dfba58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "001053e77f3d56bd61c7f467add22bab1437697387688f22f61553c52629c60c"

  strings:
    $s1 = "} while (++oo <= (tw0[\"lengt\"+\"h\"]-1));" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}