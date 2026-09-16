rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160921_b4c84c929547_2485 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return" ascii
    $s2 = "function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){r" ascii
    $s3 = "00(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s4 = "Tp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(functio" ascii
    $s5 = " \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s6 = "unction f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s7 = "turn \"SGs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(" ascii
    $s8 = "(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}