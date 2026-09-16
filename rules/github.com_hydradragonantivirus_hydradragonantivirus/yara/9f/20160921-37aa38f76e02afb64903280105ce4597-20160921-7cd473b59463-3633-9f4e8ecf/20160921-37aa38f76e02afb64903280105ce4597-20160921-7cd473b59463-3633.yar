rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_7cd473b59463_3633 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_7cd473b59463126782b9a6cfaae72835.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "0e3e3663f9696265255bc848bc98ec77487c491ee2a30b3085dbc10087b935c5"

  strings:
    $s1 = "(),(function f000(){return \"Wb\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s2 = "ction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){retur" ascii
    $s3 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s4 = "n f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"" ascii
    $s5 = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Wb\";})(),(function f" ascii
    $s6 = "){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}