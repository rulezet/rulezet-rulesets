rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_eba3e9dc8ad6_3674 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_eba3e9dc8ad614a7e5c422a93cd7b424.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "f0f6c6f4fe3daf7aae3b8d7276adbcc6577a8bf844eeae945023523b63b6cc9a"

  strings:
    $s1 = "f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\"" ascii
    $s2 = " f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"V" ascii
    $s3 = "Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functio" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii
    $s5 = "nction f000(){return \"KDh\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){retu" ascii
    $s6 = "function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}