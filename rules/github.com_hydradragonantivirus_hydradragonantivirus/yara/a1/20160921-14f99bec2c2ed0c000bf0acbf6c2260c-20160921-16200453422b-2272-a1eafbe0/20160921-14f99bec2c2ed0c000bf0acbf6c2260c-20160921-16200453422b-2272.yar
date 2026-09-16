rule _20160921_14f99bec2c2ed0c000bf0acbf6c2260c_20160921_16200453422b_2272 {
  meta:
    description = "datamaliciousorder - from files 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_b04df6930d827daddc0cb4f32f5a0ac7.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash2       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash3       = "20f05e81e91c6d1996527f4c971330eb9446dbb6ad0d88c4d97a9739264f79ba"
    hash4       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"

  strings:
    $s1 = "f000(){return \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s2 = "Gn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Yz\";})(),(function " ascii
    $s3 = "tion f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s4 = "\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f0" ascii
    $s5 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(" ascii
    $s6 = "urn \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"BMj\";})()," ascii
    $s7 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s8 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}