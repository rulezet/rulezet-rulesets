rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_66de660457cd_1494 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"

  strings:
    $s1  = "tion f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return" ascii
    $s2  = " f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp" ascii
    $s3  = "return \"OUx\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DYx\";})" ascii
    $s4  = "Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"EZu\";})(),(function" ascii
    $s5  = "eturn \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(" ascii
    $s6  = "000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa" ascii
    $s7  = "0(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";" ascii
    $s8  = "turn \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s9  = ")(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s10 = "(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){r" ascii
    $s11 = "n f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"" ascii
    $s12 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s13 = "turn \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}