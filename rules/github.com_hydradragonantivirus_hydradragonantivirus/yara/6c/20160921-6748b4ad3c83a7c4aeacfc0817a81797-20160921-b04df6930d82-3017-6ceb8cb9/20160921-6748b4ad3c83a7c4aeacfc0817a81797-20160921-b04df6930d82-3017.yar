rule _20160921_6748b4ad3c83a7c4aeacfc0817a81797_20160921_b04df6930d82_3017 {
  meta:
    description = "datamaliciousorder - from files 20160921_6748b4ad3c83a7c4aeacfc0817a81797.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e85f2791984d17e00bdb2b7163597d52bf88d9da5a0caedc977a31026ee9f7"
    hash2       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"

  strings:
    $s1 = "nction f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){retu" ascii
    $s2 = " \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(funct" ascii
    $s3 = "rn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(" ascii
    $s4 = "GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s5 = "(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s6 = "ion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s7 = "eturn \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}