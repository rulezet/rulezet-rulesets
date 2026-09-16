rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_42c93aee0243_2825 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1 = "000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg" ascii
    $s2 = "tion f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s3 = "\"Qa\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s4 = "eturn \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})()," ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s6 = "00(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";" ascii
    $s7 = "})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}