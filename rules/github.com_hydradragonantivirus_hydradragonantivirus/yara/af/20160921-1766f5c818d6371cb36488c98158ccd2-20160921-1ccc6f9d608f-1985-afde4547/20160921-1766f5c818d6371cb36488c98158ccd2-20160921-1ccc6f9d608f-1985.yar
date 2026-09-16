rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_1ccc6f9d608f_1985 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"

  strings:
    $s1 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTi\";})(),(function " ascii
    $s2 = "00(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s3 = "v\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s4 = "rn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\";})(),(f" ascii
    $s5 = "Aa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s6 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){ret" ascii
    $s7 = "00(){return \"Qa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s8 = "n f000(){return \"Br\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s9 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Sq\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}