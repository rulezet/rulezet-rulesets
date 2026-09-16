rule sig_20160525_242d6056db9288ef64fdc8dc07a4f613 {
  meta:
    description = "datamaliciousorder - file 20160525_242d6056db9288ef64fdc8dc07a4f613.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a337106e6b0c89471cb50034b9477a38c020a78e694a12e506a8d6818ede3798"

  strings:
    $s1 = "hj rav\\n;\"56x\\\\jb\" = rerednerj rav\\n;\"t36x\\\\\" = imj rav\\n;\"gn56x\\\\l\" = eixodk rav\\n;\"86x\\\\t\" = gsmk rav\\n;" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}