rule _20160921_4b85b9629682d9cbd379b3404bd09eb1_20160921_c54afc417f4f_5115 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_ded524cdc972424d0fa8254648795d71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash2       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash3       = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"

  strings:
    $s1 = "n \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s2 = "(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000()" ascii
    $s3 = "\"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(funct" ascii
    $s4 = "return \"DIa\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})()" ascii
    $s5 = "on f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}