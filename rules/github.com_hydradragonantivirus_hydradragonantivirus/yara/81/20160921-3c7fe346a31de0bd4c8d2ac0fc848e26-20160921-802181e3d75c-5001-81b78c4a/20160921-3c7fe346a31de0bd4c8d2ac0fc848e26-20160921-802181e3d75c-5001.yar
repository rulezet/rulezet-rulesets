rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_802181e3d75c_5001 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_802181e3d75c3e2d045cebba97849683.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "ion f000(){return \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s2 = " \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s3 = "nction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){retu" ascii
    $s4 = "{return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s5 = "000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"RPt" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}