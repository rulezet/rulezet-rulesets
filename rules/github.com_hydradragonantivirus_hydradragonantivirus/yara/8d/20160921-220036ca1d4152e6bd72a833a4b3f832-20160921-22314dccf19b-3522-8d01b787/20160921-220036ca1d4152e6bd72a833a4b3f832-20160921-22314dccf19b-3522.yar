rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_22314dccf19b_3522 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_22314dccf19b7c672f3deae2294f4b16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "9361b0d332b84592c527454959eb22d4191bb17c4d1acc962c192e90e96fc83e"

  strings:
    $s1 = "urn \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(" ascii
    $s2 = " \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(functi" ascii
    $s3 = "f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go" ascii
    $s4 = "tion f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s5 = "(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s6 = "){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}