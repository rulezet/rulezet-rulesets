rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_802181e3d75c_4927 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_802181e3d75c3e2d045cebba97849683.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "ab42f16384f05ce6299f1ffd60f980af6ecf1fa2d23befc951797d1d52915400"

  strings:
    $s1 = " f000(){return \"Qa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\"" ascii
    $s3 = "\"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s4 = "n \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(f" ascii
    $s5 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}