rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_2374 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash4       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"

  strings:
    $s1 = "MMz\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s2 = "ion f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s3 = "00(){return \"MMz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\"" ascii
    $s4 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){retur" ascii
    $s5 = "function f000(){return \"Br\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){re" ascii
    $s6 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){ret" ascii
    $s7 = "(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s8 = "unction f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}