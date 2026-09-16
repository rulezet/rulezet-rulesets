rule sig_20160822_656a51f3c9c3aeb0ee37c09451cc40c1 {
  meta:
    description = "datamaliciousorder - file 20160822_656a51f3c9c3aeb0ee37c09451cc40c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60971349566a70e24c319ef941f18e505c7c9d92ff864d5fb1e76236603d0d6f"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}