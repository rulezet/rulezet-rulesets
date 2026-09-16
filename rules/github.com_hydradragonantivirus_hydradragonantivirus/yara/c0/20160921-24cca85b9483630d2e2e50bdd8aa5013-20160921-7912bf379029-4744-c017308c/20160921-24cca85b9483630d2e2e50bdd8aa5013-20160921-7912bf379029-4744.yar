rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_7912bf379029_4744 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_7912bf3790296273bb8c94248adbbc9a.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "3bf106f8ef0e4b03e869f1cf914513f711eb52824441a1f2740f3faec2821404"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1 = "{return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Oh\";})" ascii
    $s2 = ")(),(function f000(){return \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(" ascii
    $s3 = "on f000(){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "ction f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){retur" ascii
    $s5 = "tion f000(){return \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}