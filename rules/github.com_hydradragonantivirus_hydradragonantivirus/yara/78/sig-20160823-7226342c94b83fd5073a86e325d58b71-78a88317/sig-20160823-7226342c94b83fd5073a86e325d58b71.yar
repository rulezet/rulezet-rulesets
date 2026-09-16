rule sig_20160823_7226342c94b83fd5073a86e325d58b71 {
  meta:
    description = "datamaliciousorder - file 20160823_7226342c94b83fd5073a86e325d58b71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cefe3e7976d4e019ca375097d7710f6676c454ea7f1322120690eebee10de2f"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}