rule _20160921_18b49c641afca0fcc3f886dc01b2641e_20160921_a7532ebefde8_1665 {
  meta:
    description = "datamaliciousorder - from files 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_d860185d3d51e8a363b423c048150940.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash2       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash3       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash4       = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"

  strings:
    $s1  = "n \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(fun" ascii
    $s2  = "n f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s3  = "(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(function f000()" ascii
    $s4  = "f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nv" ascii
    $s5  = "f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Y" ascii
    $s6  = "00(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\"" ascii
    $s7  = "n f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s8  = "return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(" ascii
    $s9  = "(function f000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Uo\";})(),(function f000(){re" ascii
    $s10 = "(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s11 = "turn \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}