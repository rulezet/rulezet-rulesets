rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_3c7fe346a31d_4924 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\"" ascii
    $s2 = "TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(functi" ascii
    $s3 = " \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s4 = "urn \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s5 = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}