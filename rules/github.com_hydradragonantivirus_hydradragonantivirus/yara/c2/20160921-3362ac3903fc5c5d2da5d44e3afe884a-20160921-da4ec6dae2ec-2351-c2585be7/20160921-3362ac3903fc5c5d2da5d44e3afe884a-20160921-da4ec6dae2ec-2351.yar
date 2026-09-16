rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_da4ec6dae2ec_2351 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "0(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"UEg\"" ascii
    $s2 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){retur" ascii
    $s3 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){retur" ascii
    $s4 = "urn \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"BMj\";})(),(f" ascii
    $s5 = "Dh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s6 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"PTi\";})(),(" ascii
    $s7 = "eturn \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()" ascii
    $s8 = "00(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Kw\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}