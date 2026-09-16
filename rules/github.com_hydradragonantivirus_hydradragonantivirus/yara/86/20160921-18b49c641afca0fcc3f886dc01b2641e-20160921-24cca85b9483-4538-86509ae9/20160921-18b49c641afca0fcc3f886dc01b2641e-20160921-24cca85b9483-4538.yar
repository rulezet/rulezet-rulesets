rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_24cca85b9483_4538 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash4       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash5       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash6       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1 = "turn \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2 = "n f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s3 = "ction f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s5 = "turn \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}