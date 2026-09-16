rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_66566a9bbc78_5123 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash3       = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"

  strings:
    $s1 = "\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function " ascii
    $s2 = "f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc" ascii
    $s3 = "unction f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s4 = "ion f000(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s5 = "function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}