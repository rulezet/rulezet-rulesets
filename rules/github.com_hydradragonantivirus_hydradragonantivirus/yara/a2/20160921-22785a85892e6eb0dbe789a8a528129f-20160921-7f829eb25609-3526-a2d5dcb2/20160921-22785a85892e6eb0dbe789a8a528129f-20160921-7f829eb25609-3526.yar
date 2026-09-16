rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_7f829eb25609_3526 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "Ux\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(functio" ascii
    $s2 = ",(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000()" ascii
    $s3 = "n \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj\";})(),(fu" ascii
    $s4 = " \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s5 = "f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu" ascii
    $s6 = "00(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}