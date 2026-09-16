rule _20160921_6d18600f3019656b0ab414a3d1a69ddb_20160921_7f829eb25609_3034 {
  meta:
    description = "datamaliciousorder - from files 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){ret" ascii
    $s2 = "ction f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Wb\";})(),(function f000(){retur" ascii
    $s3 = "Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s4 = "GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(functi" ascii
    $s5 = "(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Wb\";})(),(function f000()" ascii
    $s6 = "tion f000(){return \"Tb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return" ascii
    $s7 = "Ti\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Ml\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}