rule _20160921_7cd473b59463126782b9a6cfaae72835_20160921_939d60f07d41_1901 {
  meta:
    description = "datamaliciousorder - from files 20160921_7cd473b59463126782b9a6cfaae72835.js, 20160921_939d60f07d4171a5bae4c0b4ca33f3d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"
    hash2       = "c23bfef986de7a073bbcd781aa45ad15287fb2c448d110b92a01e652f22ff335"

  strings:
    $s1  = "j\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function" ascii
    $s2  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"UEg\";})(),(function f000(){ret" ascii
    $s3  = "0(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s4  = ")(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s5  = "ion f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(function f000(){return " ascii
    $s6  = "nction f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s7  = "ion f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return " ascii
    $s8  = " \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Oh\";})(),(func" ascii
    $s9  = "{return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(" ascii
    $s10 = "Yx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}