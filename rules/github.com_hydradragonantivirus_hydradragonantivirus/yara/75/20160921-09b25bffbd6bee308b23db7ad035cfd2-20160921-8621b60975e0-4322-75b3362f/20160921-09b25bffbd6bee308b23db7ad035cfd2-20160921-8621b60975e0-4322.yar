rule _20160921_09b25bffbd6bee308b23db7ad035cfd2_20160921_8621b60975e0_4322 {
  meta:
    description = "datamaliciousorder - from files 20160921_09b25bffbd6bee308b23db7ad035cfd2.js, 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0646df8d41668a96251f0443ca802dda915eadd4bc1fdb29b89948f4eb238893"
    hash2       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash3       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash4       = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"

  strings:
    $s1 = "turn \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})()," ascii
    $s2 = "(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";}" ascii
    $s3 = "ction f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return" ascii
    $s4 = " f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"D" ascii
    $s5 = "})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}