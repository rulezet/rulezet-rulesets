rule sig_20160822_4602ebd31a1f4007f4970ad384648ec4 {
  meta:
    description = "datamaliciousorder - file 20160822_4602ebd31a1f4007f4970ad384648ec4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d2d109c5435911c628bbbd36e8b62dd92b392a48f279acb9fb49415537705bb"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}