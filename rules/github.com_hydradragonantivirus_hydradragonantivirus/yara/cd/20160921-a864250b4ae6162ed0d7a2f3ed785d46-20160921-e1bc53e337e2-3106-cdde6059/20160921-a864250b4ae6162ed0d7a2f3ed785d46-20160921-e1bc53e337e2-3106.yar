rule _20160921_a864250b4ae6162ed0d7a2f3ed785d46_20160921_e1bc53e337e2_3106 {
  meta:
    description = "datamaliciousorder - from files 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1 = "urn \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"DYx\";})(),(" ascii
    $s2 = "n f000(){return \"QDg\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return " ascii
    $s3 = "rn \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(f" ascii
    $s4 = "),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii
    $s5 = ")(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MJq\";})(),(function f000" ascii
    $s6 = " f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s7 = "000(){return \"NYh\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}