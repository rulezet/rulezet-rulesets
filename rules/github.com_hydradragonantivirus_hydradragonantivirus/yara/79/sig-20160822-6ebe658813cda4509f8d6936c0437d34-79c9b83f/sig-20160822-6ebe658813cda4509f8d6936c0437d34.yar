rule sig_20160822_6ebe658813cda4509f8d6936c0437d34 {
  meta:
    description = "datamaliciousorder - file 20160822_6ebe658813cda4509f8d6936c0437d34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50fb2f8cc89e1f00806da90f88021900e7f3c9d9ea5fdfd2b01956813bd61cb6"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}