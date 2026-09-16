rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_7f829eb25609_2362 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "urn \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s2 = ",(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s3 = ",(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Uo\";})(),(function f000(){r" ascii
    $s4 = "on f000(){return \"Wb\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s5 = "ion f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s6 = "unction f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s7 = "function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){re" ascii
    $s8 = "GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Wb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}