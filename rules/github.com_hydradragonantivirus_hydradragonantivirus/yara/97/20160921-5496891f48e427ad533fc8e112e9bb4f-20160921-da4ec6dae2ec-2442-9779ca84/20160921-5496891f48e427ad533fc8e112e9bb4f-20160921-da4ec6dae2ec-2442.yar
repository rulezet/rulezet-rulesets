rule _20160921_5496891f48e427ad533fc8e112e9bb4f_20160921_da4ec6dae2ec_2442 {
  meta:
    description = "datamaliciousorder - from files 20160921_5496891f48e427ad533fc8e112e9bb4f.js, 20160921_da4ec6dae2eccab30a5e229082e39a40.js, 20160921_dc1d9050026f8e96fefca2306b0b5aba.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb85e1d59ed8f9cee344ab5ab95f651cb8fb1ee7ec35d0a88f8f41279a3d17a6"
    hash2       = "3bcc141cccd11dbba68b7c117d19efcd0472cb34792cc4b7e6c3d54e8a0929cc"
    hash3       = "c6189a2d5bf1254f55c8d7ad46101d9c32dc62eda1d03b19dddb22f049f8965d"
    hash4       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "{return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(" ascii
    $s2 = "on f000(){return \"Wb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii
    $s3 = "g\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4 = "(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s5 = "{return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s6 = "000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl" ascii
    $s7 = "urn \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(fu" ascii
    $s8 = "turn \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}