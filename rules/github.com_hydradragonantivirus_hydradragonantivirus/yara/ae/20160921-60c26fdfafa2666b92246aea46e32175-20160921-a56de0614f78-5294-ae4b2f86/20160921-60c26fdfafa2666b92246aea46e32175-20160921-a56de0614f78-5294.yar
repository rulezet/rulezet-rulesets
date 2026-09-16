rule _20160921_60c26fdfafa2666b92246aea46e32175_20160921_a56de0614f78_5294 {
  meta:
    description = "datamaliciousorder - from files 20160921_60c26fdfafa2666b92246aea46e32175.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4cfca41d64bbf1a0959643523d4734a108bc3ecf6147c83f60db030586c6f25"
    hash2       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash3       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "urn \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})()," ascii
    $s2 = "eturn \"DNa\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"XTn\";})(" ascii
    $s3 = " \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(functi" ascii
    $s4 = "tion f000(){return \"Wy\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return" ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}