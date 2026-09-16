rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_24cca85b9483_4540 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_970f1dd445269cda0ba5e6f9fd675983.js, 20160921_a31336f192353e1997fed06b582e1aef.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash3       = "eb33bb458042e91be0620012d2d05aaafd9742abb0880d1389b5c02b834e9290"
    hash4       = "762774d5263bffcad635355a63715b9cd26c09b53efe134be033e8dff5062b47"
    hash5       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash6       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash7       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1 = "ion f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return " ascii
    $s2 = "rn \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(fu" ascii
    $s3 = "(),(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(" ascii
    $s4 = "000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx" ascii
    $s5 = "ion f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}