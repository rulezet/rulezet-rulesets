rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_1766f5c818d6_4405 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash3       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash4       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000()" ascii
    $s2 = "00(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\"" ascii
    $s3 = "on f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s4 = "turn \"OUx\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})()," ascii
    $s5 = "Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qz\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}