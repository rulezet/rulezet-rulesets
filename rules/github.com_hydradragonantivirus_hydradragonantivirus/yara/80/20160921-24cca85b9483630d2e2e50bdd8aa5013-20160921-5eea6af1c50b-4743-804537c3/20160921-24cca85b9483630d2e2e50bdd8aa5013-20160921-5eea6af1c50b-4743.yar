rule _20160921_24cca85b9483630d2e2e50bdd8aa5013_20160921_5eea6af1c50b_4743 {
  meta:
    description = "datamaliciousorder - from files 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash2       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash3       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"

  strings:
    $s1 = "rn \"Nv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s2 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"V" ascii
    $s3 = ",(function f000(){return \"SGs\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s4 = "{return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"PTi\";})(" ascii
    $s5 = "turn \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}