rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_da4ec6dae2ec_3784 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"

  strings:
    $s1 = "g\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s2 = "on f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s3 = " f000(){return \"GGn\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"O" ascii
    $s4 = "urn \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s5 = "(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\"" ascii
    $s6 = "unction f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}