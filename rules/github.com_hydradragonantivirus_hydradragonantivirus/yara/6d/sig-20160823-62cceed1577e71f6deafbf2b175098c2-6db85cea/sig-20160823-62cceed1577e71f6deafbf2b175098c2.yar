rule sig_20160823_62cceed1577e71f6deafbf2b175098c2 {
  meta:
    description = "datamaliciousorder - file 20160823_62cceed1577e71f6deafbf2b175098c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6290285968a1bd4b74105cfc318acdd45f0ded88dd18d8c29fd6bbea55311c34"

  strings:
    $s1 = "var Nt0 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}