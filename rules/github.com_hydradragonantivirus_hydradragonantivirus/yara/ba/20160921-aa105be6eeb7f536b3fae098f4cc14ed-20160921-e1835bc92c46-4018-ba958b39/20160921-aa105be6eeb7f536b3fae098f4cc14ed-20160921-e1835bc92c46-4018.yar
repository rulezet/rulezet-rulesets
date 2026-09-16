rule _20160921_aa105be6eeb7f536b3fae098f4cc14ed_20160921_e1835bc92c46_4018 {
  meta:
    description = "datamaliciousorder - from files 20160921_aa105be6eeb7f536b3fae098f4cc14ed.js, 20160921_e1835bc92c4604db194bc49df621cade.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df7bae330cc77ba04437c13d3843c951b5c3db558d70c922c4f339dfdc29abbd"
    hash2       = "ca98fbe0aef0208d6ee3df93c692fee8802fb2206893dc56e723bc4af714c0fd"

  strings:
    $s1 = "return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})()" ascii
    $s2 = "unction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){ret" ascii
    $s3 = "turn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})()" ascii
    $s4 = "{return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})" ascii
    $s5 = "ction f000(){return \"SEo\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii
    $s6 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Kw\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}