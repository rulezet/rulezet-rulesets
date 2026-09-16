rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_fd5fc0674575_4890 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = ";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f00" ascii
    $s2 = "function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){ret" ascii
    $s3 = "ion f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s4 = "f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj" ascii
    $s5 = "eturn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}