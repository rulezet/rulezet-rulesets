rule _20160921_1de6da840ee50be73263cde38bfe05f8_20160921_2eacd3ef1ce6_4622 {
  meta:
    description = "datamaliciousorder - from files 20160921_1de6da840ee50be73263cde38bfe05f8.js, 20160921_2eacd3ef1ce6866325342ce8cba80e38.js, 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c58fd3e89dda2f745d131d428bf5c447e7f5e2bdee82bb72c417d8a0be878a"
    hash2       = "128e4fae256d5c8ef6708fbd7f51b17e3da126d63b88361b0e92c9808a0c393f"
    hash3       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash4       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1 = "000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"DYx" ascii
    $s2 = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s3 = "})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f0" ascii
    $s4 = "rn \"ZIi\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s5 = " f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}