rule sig_20160208_ed25bfb96f2d56ada52420464667714d {
  meta:
    description = "datamaliciousorder - file 20160208_ed25bfb96f2d56ada52420464667714d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d14004f2cb69f7f0c6f17ef0bea8b890f26dfe2ce249091894fc148afd85759"

  strings:
    $s1 = "e'] = function() {" fullword ascii
    $s2 = "    aPQs599ov['onr' + ('AqHnx', 'cT9FiX', 'Tb1d', 'e') + 'a' + ('0qD', 'FYvV', 'WP2', 'd') + 'ys' + ('KTN', '5GHL', 'FeSQg6', 't" ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}