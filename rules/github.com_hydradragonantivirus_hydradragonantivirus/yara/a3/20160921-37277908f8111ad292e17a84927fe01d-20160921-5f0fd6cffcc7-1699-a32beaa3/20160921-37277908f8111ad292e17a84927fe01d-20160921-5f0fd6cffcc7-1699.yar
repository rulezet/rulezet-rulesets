rule _20160921_37277908f8111ad292e17a84927fe01d_20160921_5f0fd6cffcc7_1699 {
  meta:
    description = "datamaliciousorder - from files 20160921_37277908f8111ad292e17a84927fe01d.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac56e804b2f49b3fcd9bbc13fbdc4deb3a0ef68848e6527c15ab41f1104f286"
    hash2       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"

  strings:
    $s1  = "0(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\"" ascii
    $s2  = "nction f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return" ascii
    $s3  = "nction f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OMd\";})(),(function f000(){retu" ascii
    $s4  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(f" ascii
    $s5  = "function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s6  = "){return \"DYx\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";" ascii
    $s7  = "n \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(func" ascii
    $s8  = "000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn" ascii
    $s9  = "00(){return \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yv\"" ascii
    $s10 = "unction f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function f000(){retu" ascii
    $s11 = "n\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}