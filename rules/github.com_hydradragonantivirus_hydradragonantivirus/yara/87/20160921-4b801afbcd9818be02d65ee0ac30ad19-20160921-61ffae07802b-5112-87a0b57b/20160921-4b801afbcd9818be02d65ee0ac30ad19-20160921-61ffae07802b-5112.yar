rule _20160921_4b801afbcd9818be02d65ee0ac30ad19_20160921_61ffae07802b_5112 {
  meta:
    description = "datamaliciousorder - from files 20160921_4b801afbcd9818be02d65ee0ac30ad19.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f85dba2504097034fa23d87391ecdaf7fe5f29824616a8d91d353284964bfac1"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"

  strings:
    $s1 = "return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})()" ascii
    $s2 = "GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s3 = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(func" ascii
    $s4 = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s5 = "on f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}