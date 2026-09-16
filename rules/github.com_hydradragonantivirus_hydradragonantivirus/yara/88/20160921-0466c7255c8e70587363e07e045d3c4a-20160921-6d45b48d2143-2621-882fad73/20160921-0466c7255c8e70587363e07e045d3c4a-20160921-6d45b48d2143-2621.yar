rule _20160921_0466c7255c8e70587363e07e045d3c4a_20160921_6d45b48d2143_2621 {
  meta:
    description = "datamaliciousorder - from files 20160921_0466c7255c8e70587363e07e045d3c4a.js, 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a4fdb08cf486e569a48a599a4a2c53d91892166b2194b7066e39c535723f8f"
    hash2       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"

  strings:
    $s1 = "(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){re" ascii
    $s2 = "o\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function " ascii
    $s3 = "return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\";})(" ascii
    $s4 = "ion f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return " ascii
    $s5 = "unction f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s6 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nv\";})(),(function f000()" ascii
    $s7 = "0(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}