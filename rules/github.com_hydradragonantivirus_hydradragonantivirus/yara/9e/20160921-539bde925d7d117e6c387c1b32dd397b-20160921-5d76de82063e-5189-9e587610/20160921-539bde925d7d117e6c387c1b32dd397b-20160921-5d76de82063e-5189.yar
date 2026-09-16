rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_5d76de82063e_5189 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_5d76de82063e28ac2a0fc9a6ce296761.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "4e44228eb55ff969128759659f37a0c5ebdeb5fc653b3b206ba5fa42d8e30166"
    hash3       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"

  strings:
    $s1 = " \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(fun" ascii
    $s2 = "n f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s3 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retur" ascii
    $s4 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Yz\";})(),(function" ascii
    $s5 = "urn \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}