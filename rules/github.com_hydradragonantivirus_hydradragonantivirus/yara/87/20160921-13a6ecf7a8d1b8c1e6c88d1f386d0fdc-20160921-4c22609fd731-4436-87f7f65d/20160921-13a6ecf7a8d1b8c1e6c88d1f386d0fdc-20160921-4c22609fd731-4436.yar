rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_4c22609fd731_4436 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_4c22609fd7310d7f415ca007620a244b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"

  strings:
    $s1 = " \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(func" ascii
    $s2 = " \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(func" ascii
    $s3 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"UEg\";})(),(functi" ascii
    $s4 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Sq\";})(),(functi" ascii
    $s5 = "unction f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}