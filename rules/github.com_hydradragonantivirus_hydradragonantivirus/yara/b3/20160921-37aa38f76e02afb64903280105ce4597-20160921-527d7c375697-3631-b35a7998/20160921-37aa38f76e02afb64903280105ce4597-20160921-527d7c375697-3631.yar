rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_527d7c375697_3631 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_527d7c3756974f804734da343b6b6f0e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"

  strings:
    $s1 = "0(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";" ascii
    $s2 = " f000(){return \"Sv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s3 = "function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii
    $s4 = "n \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s5 = "n \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s6 = "Dh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}