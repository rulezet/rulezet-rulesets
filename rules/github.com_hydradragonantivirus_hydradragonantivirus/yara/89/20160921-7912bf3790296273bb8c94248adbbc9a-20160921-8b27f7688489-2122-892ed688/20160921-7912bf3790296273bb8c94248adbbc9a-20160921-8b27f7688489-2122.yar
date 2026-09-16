rule _20160921_7912bf3790296273bb8c94248adbbc9a_20160921_8b27f7688489_2122 {
  meta:
    description = "datamaliciousorder - from files 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "eturn \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})()," ascii
    $s2 = "{return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"KXg\";})(" ascii
    $s3 = "eturn \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})()" ascii
    $s4 = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s5 = "unction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DNa\";})(),(function f000(){re" ascii
    $s6 = "Go\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"RPt\";})(),(functio" ascii
    $s7 = "return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Lp\";})()," ascii
    $s8 = ",(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s9 = " f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Z" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}