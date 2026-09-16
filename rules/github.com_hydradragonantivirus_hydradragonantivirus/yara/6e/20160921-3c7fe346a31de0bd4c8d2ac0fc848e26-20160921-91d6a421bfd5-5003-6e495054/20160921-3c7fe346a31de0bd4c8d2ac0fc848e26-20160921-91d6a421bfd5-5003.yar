rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_5003 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_ad69715850fae108d9a16055efb4f51c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash4       = "76ed8c5c3ace4ce119f1561d5d61ca2e454da79e9156a8397e72d6eed3a22d74"

  strings:
    $s1 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000" ascii
    $s2 = "eturn \"MMz\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(" ascii
    $s3 = "\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function " ascii
    $s4 = "nction f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s5 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}