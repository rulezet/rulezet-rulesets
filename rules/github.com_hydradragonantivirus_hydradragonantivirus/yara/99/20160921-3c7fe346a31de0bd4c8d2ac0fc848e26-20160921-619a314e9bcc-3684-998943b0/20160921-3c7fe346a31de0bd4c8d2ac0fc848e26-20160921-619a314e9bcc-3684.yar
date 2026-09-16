rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_619a314e9bcc_3684 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_619a314e9bcca286c046dff250b54b6b.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "9f370548310908c52102d40d56781574ad404eafca7ac832d5e52d48f722bff5"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s2 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){re" ascii
    $s3 = ")(),(function f000(){return \"Vu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000()" ascii
    $s4 = "000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\"" ascii
    $s5 = "f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu" ascii
    $s6 = " f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"O" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}