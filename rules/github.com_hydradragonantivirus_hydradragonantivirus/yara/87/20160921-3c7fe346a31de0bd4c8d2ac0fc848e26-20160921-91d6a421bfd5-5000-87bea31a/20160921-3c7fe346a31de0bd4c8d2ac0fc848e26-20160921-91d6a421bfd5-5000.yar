rule _20160921_3c7fe346a31de0bd4c8d2ac0fc848e26_20160921_91d6a421bfd5_5000 {
  meta:
    description = "datamaliciousorder - from files 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_fff847efa0eaa326a0aad4d2fc81d41e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash2       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash3       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash4       = "93f868a10878cb41f305e28c8802778903c99b84a1bc0647a0c2c78fd6310577"

  strings:
    $s1 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Nv\";})(),(function f000(){re" ascii
    $s2 = "rn \"OUx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s3 = "),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Vj\";})(),(function f000()" ascii
    $s4 = "0(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";" ascii
    $s5 = "000(){return \"RLk\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}