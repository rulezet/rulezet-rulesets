rule _20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477_20160921_cb7b906c44a3_5511 {
  meta:
    description = "datamaliciousorder - from files 20160921_8ab8e9ec61d829b3b36dc8e0cbc3b477.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6302a5443fa0c0309aa33e24b90ed81d05258a2a800cda52321e903fc44e0494"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1 = "g\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function" ascii
    $s2 = "n \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s3 = "n f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"G" ascii
    $s4 = "00(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";" ascii
    $s5 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}