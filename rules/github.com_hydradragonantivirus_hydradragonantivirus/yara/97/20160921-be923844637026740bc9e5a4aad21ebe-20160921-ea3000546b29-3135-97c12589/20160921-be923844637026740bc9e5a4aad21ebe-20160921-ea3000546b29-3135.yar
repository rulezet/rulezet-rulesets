rule _20160921_be923844637026740bc9e5a4aad21ebe_20160921_ea3000546b29_3135 {
  meta:
    description = "datamaliciousorder - from files 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_ea3000546b29aee563be9d58318d1857.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash2       = "eb46ac22bc2e86a5bacf6fbfffe3a746600369a5d28c84d095b1269bcdfe9cc6"
    hash3       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"DYx\"" ascii
    $s2 = "ZIi\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s3 = "rn \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s4 = "(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"DIa\"" ascii
    $s5 = "n f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TK" ascii
    $s6 = "turn \"Qa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s7 = "DAp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}