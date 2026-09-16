rule _20160921_23ef471e720525eb3dff80c2296d1a60_20160921_35e8549205da_4735 {
  meta:
    description = "datamaliciousorder - from files 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash2       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash3       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash4       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash5       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = " f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"D" ascii
    $s2 = "return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s3 = "unction f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){retu" ascii
    $s4 = "urn \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s5 = "(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}