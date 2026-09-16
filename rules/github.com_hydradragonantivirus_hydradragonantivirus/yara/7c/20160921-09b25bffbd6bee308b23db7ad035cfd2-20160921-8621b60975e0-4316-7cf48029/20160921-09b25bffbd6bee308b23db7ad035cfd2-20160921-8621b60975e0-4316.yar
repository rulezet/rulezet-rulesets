rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_8621b60975e0_4316 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"

  strings:
    $s1 = "urn \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(" ascii
    $s2 = ",(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s3 = "000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do" ascii
    $s4 = "rn \"Zj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(fu" ascii
    $s5 = "{return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}