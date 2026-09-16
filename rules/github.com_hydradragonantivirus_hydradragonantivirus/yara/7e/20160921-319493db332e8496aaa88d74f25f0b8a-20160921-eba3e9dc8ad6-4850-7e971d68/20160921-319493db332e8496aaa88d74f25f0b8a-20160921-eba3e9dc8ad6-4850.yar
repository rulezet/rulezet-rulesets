rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_eba3e9dc8ad6_4850 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "000(){return \"MJq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj" ascii
    $s2 = "n \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s3 = "){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})" ascii
    $s4 = "(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})(),(function f000(){r" ascii
    $s5 = "function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}