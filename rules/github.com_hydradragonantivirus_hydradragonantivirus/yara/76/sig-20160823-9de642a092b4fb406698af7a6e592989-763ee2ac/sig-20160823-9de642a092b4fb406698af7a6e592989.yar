rule sig_20160823_9de642a092b4fb406698af7a6e592989 {
  meta:
    description = "datamaliciousorder - file 20160823_9de642a092b4fb406698af7a6e592989.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b3d1aa1941f50188b70f52091d36c5c479a7cc1cbe99619dfaa58bbaf1c7f126"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}