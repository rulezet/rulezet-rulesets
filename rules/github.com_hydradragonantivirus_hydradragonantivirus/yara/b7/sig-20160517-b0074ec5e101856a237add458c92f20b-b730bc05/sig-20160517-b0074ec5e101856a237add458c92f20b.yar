rule sig_20160517_b0074ec5e101856a237add458c92f20b {
  meta:
    description = "datamaliciousorder - file 20160517_b0074ec5e101856a237add458c92f20b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d506ed5cb64a95e35b79ad1a9a7d1350695fa942ccb7498f318a573059cf9dd7"

  strings:
    $s1 = "var n1dw='var43xamyjnwrha1nf ty2yqexrwpx3eboshuzu3ew3tevjwnix1slce1kizkqar2ukjyzdrpkiljq=wjzdx\\'izuwrtscsuocpztj1nr3ynfilyrbift" ascii
    $s2 = "fsxtorkm411yurtoje,crarl0cdxs3 padle xdchwpy4zy4,ej';var uoxja='wmw dcngy gjb2b;qaglq u4xvl0ssosq)aq4oc jujna urnms oux4g ztkko " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}