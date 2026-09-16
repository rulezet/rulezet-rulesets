rule _20160921_cb7b906c44a337d403a375918e9db0c5_20160921_e59567324a54_5688 {
  meta:
    description = "datamaliciousorder - from files 20160921_cb7b906c44a337d403a375918e9db0c5.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"
    hash2       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "){return \"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(" ascii
    $s2 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s3 = ",(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){re" ascii
    $s4 = "(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s5 = " f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}