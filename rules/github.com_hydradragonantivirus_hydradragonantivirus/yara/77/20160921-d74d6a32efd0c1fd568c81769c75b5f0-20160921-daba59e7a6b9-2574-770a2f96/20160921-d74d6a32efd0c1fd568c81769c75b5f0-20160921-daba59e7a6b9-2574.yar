rule _20160921_d74d6a32efd0c1fd568c81769c75b5f0_20160921_daba59e7a6b9_2574 {
  meta:
    description = "datamaliciousorder - from files 20160921_d74d6a32efd0c1fd568c81769c75b5f0.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eeb2c0427dff61d2dceedf890b96f76da6a37634fefa03079a481c476d7a3547"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){retu" ascii
    $s2 = "{return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(" ascii
    $s3 = "nction f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){retu" ascii
    $s4 = "),(function f000(){return \"Yz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s5 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"DIa\";})(),(function f0" ascii
    $s6 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s7 = "ion f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s8 = "(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}