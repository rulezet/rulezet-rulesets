rule _20160921_b32c8921e3390cb8f9450436f4e43cfb_20160921_daba59e7a6b9_1924 {
  meta:
    description = "datamaliciousorder - from files 20160921_b32c8921e3390cb8f9450436f4e43cfb.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ab35ff2eba15a460823fc709e29f7c1041f054096a3690e92c926943d39d6a8"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return " ascii
    $s2  = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000" ascii
    $s3  = "on f000(){return \"MDb\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s4  = "n \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5  = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DNa\";})(),(function " ascii
    $s6  = "function f000(){return \"XTn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s7  = "})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})(),(function f00" ascii
    $s8  = "000(){return \"Lp\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh" ascii
    $s9  = "turn \"RLk\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"GGn\";})()" ascii
    $s10 = "on f000(){return \"DAp\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}