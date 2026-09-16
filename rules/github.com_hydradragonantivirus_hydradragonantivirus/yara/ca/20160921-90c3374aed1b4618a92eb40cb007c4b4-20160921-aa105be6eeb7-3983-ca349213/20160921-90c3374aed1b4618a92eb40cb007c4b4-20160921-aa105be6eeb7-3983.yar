rule _20160921_90c3374aed1b4618a92eb40cb007c4b4_20160921_aa105be6eeb7_3983 {
  meta:
    description = "datamaliciousorder - from files 20160921_90c3374aed1b4618a92eb40cb007c4b4.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "42b3d35e818b5b373b42427cc936c0a099078535d6f37eb5d4dc22b8ac1ee151"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = " \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(fun" ascii
    $s2 = "Tn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3 = "turn \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})()," ascii
    $s4 = "{return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(" ascii
    $s5 = "unction f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s6 = "ion f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}