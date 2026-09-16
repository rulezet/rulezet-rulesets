rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_a7532ebefde8_3440 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash3       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash4       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})()" ascii
    $s2 = "n \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(fu" ascii
    $s3 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function " ascii
    $s4 = "000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s5 = "urn \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s6 = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}