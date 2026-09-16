rule sig_20160823_8c67efac48dfe7514427bd95d48463d2 {
  meta:
    description = "datamaliciousorder - file 20160823_8c67efac48dfe7514427bd95d48463d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "266d770d7276152fdff7dd9b29030519321a4144c4ae21ae8180a10d9e3e3384"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}