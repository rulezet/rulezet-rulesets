rule sig_20160822_3ba0d4db0472563f373ffce6e9174ba9 {
  meta:
    description = "datamaliciousorder - file 20160822_3ba0d4db0472563f373ffce6e9174ba9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abdfdaa03b921fb8bc0e3daf1e890507f5271528902e11cbebb24f8524efce40"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}