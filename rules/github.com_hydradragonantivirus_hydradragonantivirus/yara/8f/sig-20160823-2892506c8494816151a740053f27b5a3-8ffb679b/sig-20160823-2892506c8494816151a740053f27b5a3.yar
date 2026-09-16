rule sig_20160823_2892506c8494816151a740053f27b5a3 {
  meta:
    description = "datamaliciousorder - file 20160823_2892506c8494816151a740053f27b5a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508f1e4509cb9bb6d32660374a2aff92e6a24eaae00a14127eb03b1437af219c"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}