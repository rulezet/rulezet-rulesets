rule _20160921_5f5611940db748f8f47ad6671e45ac27_20160921_aa105be6eeb7_5287 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash2       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"

  strings:
    $s1 = " \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s2 = "tion f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"U" ascii
    $s4 = "m\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s5 = "turn \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}