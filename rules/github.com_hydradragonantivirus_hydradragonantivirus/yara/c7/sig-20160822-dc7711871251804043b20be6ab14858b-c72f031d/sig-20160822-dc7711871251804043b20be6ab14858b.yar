rule sig_20160822_dc7711871251804043b20be6ab14858b {
  meta:
    description = "datamaliciousorder - file 20160822_dc7711871251804043b20be6ab14858b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a9171b41f801306f94d0c15efe236ac6527f5ed43279f07d0f28d5752a45609"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}