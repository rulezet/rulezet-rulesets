rule sig_20160822_14fdf205bf21dce03ad8ba7a0e59e8f0 {
  meta:
    description = "datamaliciousorder - file 20160822_14fdf205bf21dce03ad8ba7a0e59e8f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06452380b9fcc42da482df74d9c03108a098b934f426432918426ff88434896e"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}