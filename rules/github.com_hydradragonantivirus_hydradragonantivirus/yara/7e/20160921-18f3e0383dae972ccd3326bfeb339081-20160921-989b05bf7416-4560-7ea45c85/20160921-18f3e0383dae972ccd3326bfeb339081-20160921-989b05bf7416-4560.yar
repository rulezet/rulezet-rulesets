rule _20160921_18f3e0383dae972ccd3326bfeb339081_20160921_989b05bf7416_4560 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3e0383dae972ccd3326bfeb339081.js, 20160921_989b05bf7416ad8ff0b583666028a2c1.js, 20160922_7e0b1e5964974c7e845016e40a3ad891.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350a94fd53479bde96c18236897fe9846647bd4d4471ff812cc45a165d90a9d0"
    hash2       = "c3c2ebe9b3cb36288422e9757d55c015e9201e8ed349ea0a4f3fb5c4042fbfb3"
    hash3       = "de6271315a5e75cb84cc0796ab51f8e68b1d166a3e7393cc14d81a37883277cd"

  strings:
    $s1 = "(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"WIj\";})(),(function f000()" ascii
    $s2 = "n f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"" ascii
    $s3 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"WIj\";})(),(function f000" ascii
    $s4 = "return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yz\";})()," ascii
    $s5 = "(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}