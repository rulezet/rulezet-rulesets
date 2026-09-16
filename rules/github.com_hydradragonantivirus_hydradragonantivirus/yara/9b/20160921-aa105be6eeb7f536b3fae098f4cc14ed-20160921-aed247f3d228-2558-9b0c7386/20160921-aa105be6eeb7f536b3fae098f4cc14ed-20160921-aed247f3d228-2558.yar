rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_aed247f3d228_2558 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_aed247f3d2282ef44bd04021d1a47ef8.js, 20160921_b9bf4d00098353791f6752da8f2fba0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "163159bd2bdf088e94bb401b56d374651d890ca6420982f4654021ab58ff2e2d"
    hash3       = "fb6ed05e313f10d63719b3d6465378a522453c08ee11e88d9852f5e4ba4f69fa"

  strings:
    $s1 = "0(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = "(function f000(){return \"RPt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s3 = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";}" ascii
    $s4 = "(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){ret" ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s6 = " \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s7 = "rn \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(f" ascii
    $s8 = "Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"MMz\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}