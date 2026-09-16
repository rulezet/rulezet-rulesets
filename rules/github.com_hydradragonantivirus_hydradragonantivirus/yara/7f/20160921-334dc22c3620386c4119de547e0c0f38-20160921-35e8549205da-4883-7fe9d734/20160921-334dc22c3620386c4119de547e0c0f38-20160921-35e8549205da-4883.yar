rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_35e8549205da_4883 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash3       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash4       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash5       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash6       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash7       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "turn \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(" ascii
    $s2 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DIa\";})(),(function f000(" ascii
    $s3 = "on f000(){return \"Mu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s4 = ";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii
    $s5 = "return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}