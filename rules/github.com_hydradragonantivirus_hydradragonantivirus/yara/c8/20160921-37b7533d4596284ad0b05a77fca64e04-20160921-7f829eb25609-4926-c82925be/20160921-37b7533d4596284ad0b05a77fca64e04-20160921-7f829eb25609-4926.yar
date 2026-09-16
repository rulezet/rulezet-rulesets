rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_7f829eb25609_4926 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_7f829eb25609c6f6d37ef18f9c4f8ad7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "cbb0232bbf0751233c3e647bef431987aa4666e8c60b9ff699f55e31318c3e22"

  strings:
    $s1 = "\"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s2 = "00(){return \"Wh\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IPu\"" ascii
    $s3 = "})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f0" ascii
    $s4 = "h\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function " ascii
    $s5 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}