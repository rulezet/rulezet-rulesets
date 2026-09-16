rule _20160921_37b7533d4596284ad0b05a77fca64e04_20160921_cf2bd9606d39_3637 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b7533d4596284ad0b05a77fca64e04.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61b41be208c77057ce2b56a866ae0e936c6372d0c3a92f126a1cf5090fe0a5e7"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = "Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DYx\";})(),(functio" ascii
    $s2 = "MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii
    $s3 = "(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";}" ascii
    $s5 = "b\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(functio" ascii
    $s6 = "ction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}