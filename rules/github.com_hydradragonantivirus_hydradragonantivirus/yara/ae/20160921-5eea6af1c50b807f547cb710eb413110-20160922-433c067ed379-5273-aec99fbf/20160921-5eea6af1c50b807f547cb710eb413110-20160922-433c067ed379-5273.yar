rule _20160921_5eea6af1c50b807f547cb710eb413110_20160922_433c067ed379_5273 {
  meta:
    description = "datamaliciousorder - from files 20160921_5eea6af1c50b807f547cb710eb413110.js, 20160922_433c067ed37935e72b4e47664c370c44.js, 20160922_b640840d7ced127a08912e8c9296d442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0791148d3e03ce3d231765cb1183a7c90ac5567405736f3d6780502908893b46"
    hash2       = "9070188f3e02706e771ccc37b9b462d58035283f00f156012a41459fa5293e32"
    hash3       = "a67ca3e1e87611dc94e916e6896d144c03fa7f8a6411fdeb74092be2a79bcad4"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Wb\";})(),(func" ascii
    $s2 = "(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qj\";" ascii
    $s3 = "00(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn" ascii
    $s4 = "nction f000(){return \"Kw\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s5 = "0(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}