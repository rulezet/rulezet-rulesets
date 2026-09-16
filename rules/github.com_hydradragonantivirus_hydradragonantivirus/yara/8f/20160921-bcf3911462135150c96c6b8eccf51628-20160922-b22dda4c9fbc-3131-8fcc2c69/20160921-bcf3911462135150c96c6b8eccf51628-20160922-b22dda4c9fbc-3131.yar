rule _20160921_bcf3911462135150c96c6b8eccf51628_20160922_b22dda4c9fbc_3131 {
  meta:
    description = "datamaliciousorder - from files 20160921_bcf3911462135150c96c6b8eccf51628.js, 20160922_b22dda4c9fbc74ba5e251fc3110ada5a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"
    hash2       = "946b208e84c64dbffc7e1cb08a19f629639d795decea5bf8ddd08b34a59e5e59"

  strings:
    $s1 = "Lp\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2 = "unction f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s3 = "00(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Yz\"" ascii
    $s4 = "(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})" ascii
    $s5 = "turn \"Sj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(" ascii
    $s6 = "ion f000(){return \"WIj\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return" ascii
    $s7 = "WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"ZFe\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}