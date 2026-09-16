rule _20160921_6d45b48d21435a8cdd305a8a7d2405a3_20160921_a3beeaf53744_5368 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d45b48d21435a8cdd305a8a7d2405a3.js, 20160921_a3beeaf5374452a126fde6e8bd845f1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa45b1317b967bb6337124692b84f1082b2294f82eaae64362d2c8cac37b2779"
    hash2       = "b85118fedd76dd449fd30cfd693681aa77891d92c19c3fa0e9dd14f034e867bb"

  strings:
    $s1 = ";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f0" ascii
    $s2 = "(){return \"DYx\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"EZu\";" ascii
    $s3 = "nction f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){retur" ascii
    $s4 = ")(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000" ascii
    $s5 = "urn \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}