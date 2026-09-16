rule _20160921_02b826231ece268e91633311d2c70554_20160921_06b8a8ba37bd_4139 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_06b8a8ba37bdbe66227238ed6343de45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "49865219ca3278a1a02bfd25fc25cac90e7685a0b5083a98acee0c82fc74d77b"

  strings:
    $s1 = "return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})()" ascii
    $s2 = "0(){return \"QDg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\"" ascii
    $s3 = "0(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"HJm\";" ascii
    $s4 = "nction f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s5 = "0(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DYx\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}