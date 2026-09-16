rule _20160921_74aa1eb054c4d9cf85bcad2468e8404a_20160922_f0d656e55be0_3913 {
  meta:
    description = "datamaliciousorder - from files 20160921_74aa1eb054c4d9cf85bcad2468e8404a.js, 20160922_f0d656e55be0c93b2b5e1f0eda45da9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74bb8f886c1de9aea157cf5ee2e1b8c02b30df1117e95e18ef3a2d5dc44277ad"
    hash2       = "276c24e399a13bf7907294578800d75620fb48bcd34bc84b9d92448375c72d37"

  strings:
    $s1 = "0(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";" ascii
    $s2 = "nction f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return" ascii
    $s3 = " f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Q" ascii
    $s4 = "eturn \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})()," ascii
    $s5 = "n \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(func" ascii
    $s6 = "eturn \"Ot\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}