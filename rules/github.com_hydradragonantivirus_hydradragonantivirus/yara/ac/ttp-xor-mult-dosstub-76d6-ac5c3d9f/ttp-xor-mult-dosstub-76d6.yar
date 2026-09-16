rule TTP_XOR_MULT_DOSStub_76d6 {
  strings:
    $key_76d6 = { 22 be [2] 56 a6 [2] 11 a4 [2] 56 b5 [2] 18 b9 [2] 14 b3 [2] 03 b8 [2] 18 f6 [2] 25 }

  condition:
    any of them
}