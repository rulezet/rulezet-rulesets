rule _20160921_13e37e5857b4357c4b5f40a021143101_20160921_3c7fe346a31d_3393 {
  meta:
    description = "datamaliciousorder - from files 20160921_13e37e5857b4357c4b5f40a021143101.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd94ae3a0c3b8dadcaba65cdd5f58ebd19d616ac5679af1b7891e5bf26889265"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Kw\";})(),(funct" ascii
    $s2 = "n\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function " ascii
    $s3 = "i\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s4 = "Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(functi" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(f" ascii
    $s6 = "ion f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}