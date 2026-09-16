rule sig_20160823_f9024058e489de091ae907a262c2e537 {
  meta:
    description = "datamaliciousorder - file 20160823_f9024058e489de091ae907a262c2e537.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5af9a9c290d3117a92be60272f894a5155fc91d4a67d0a6e28970735ee2e52"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}