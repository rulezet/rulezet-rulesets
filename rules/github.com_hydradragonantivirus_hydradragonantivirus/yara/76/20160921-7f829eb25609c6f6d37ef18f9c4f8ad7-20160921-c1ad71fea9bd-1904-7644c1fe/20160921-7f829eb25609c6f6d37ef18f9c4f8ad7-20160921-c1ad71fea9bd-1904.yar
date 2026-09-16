rule _20160921_7f829eb25609c6f6d37ef18f9c4f8ad7_20160921_c1ad71fea9bd_1904 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1  = " f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s2  = "eturn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})()" ascii
    $s3  = "f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do" ascii
    $s4  = "000(){return \"DYs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg" ascii
    $s5  = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"DNa\";})(),(function f000" ascii
    $s6  = "Eo\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s7  = "on f000(){return \"MMz\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return " ascii
    $s8  = "urn \"SEo\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yz\";})(),(fu" ascii
    $s9  = "return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Wb\";})()" ascii
    $s10 = "\"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}