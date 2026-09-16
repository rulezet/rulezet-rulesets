rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_80e6ac924bf1_3683 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"
    hash3       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash4       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"

  strings:
    $s1 = "\"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s2 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){retu" ascii
    $s3 = "n \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s4 = "urn \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s5 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s6 = "x\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}