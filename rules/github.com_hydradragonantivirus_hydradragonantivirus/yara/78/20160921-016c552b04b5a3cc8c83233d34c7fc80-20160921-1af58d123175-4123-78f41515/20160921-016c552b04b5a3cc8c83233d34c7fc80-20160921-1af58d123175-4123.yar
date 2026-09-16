rule _20160921_016c552b04b5a3cc8c83233d34c7fc80_20160921_1af58d123175_4123 {
  meta:
    description = "datamaliciousorder - from files 20160921_016c552b04b5a3cc8c83233d34c7fc80.js, 20160921_1af58d1231756b320d04226685b5a131.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a691692f0982e93fd21c441e8c6d39328f1ea5990ce24999b2df98ee3488f667"
    hash2       = "de59166ad132c3c5ad12a85d2d837c1aec192afb497be23c517c637a08d25171"
    hash3       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash4       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash5       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){re" ascii
    $s2 = "00(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s3 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){ret" ascii
    $s4 = "n \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(fun" ascii
    $s5 = "0(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}