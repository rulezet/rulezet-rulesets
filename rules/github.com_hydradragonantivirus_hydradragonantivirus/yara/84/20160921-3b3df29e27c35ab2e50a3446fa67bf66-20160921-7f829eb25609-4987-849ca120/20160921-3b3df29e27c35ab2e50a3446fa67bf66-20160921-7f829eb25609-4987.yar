rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_7f829eb25609_4987 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(function f000" ascii
    $s2 = "{return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(" ascii
    $s3 = "on f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){" ascii
    $s5 = "\"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vj\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}