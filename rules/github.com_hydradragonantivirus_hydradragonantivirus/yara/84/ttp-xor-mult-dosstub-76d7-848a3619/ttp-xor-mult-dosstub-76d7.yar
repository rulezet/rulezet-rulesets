rule TTP_XOR_MULT_DOSStub_76d7 {
  strings:
    $key_76d7 = { 22 bf [2] 56 a7 [2] 11 a5 [2] 56 b4 [2] 18 b8 [2] 14 b2 [2] 03 b9 [2] 18 f7 [2] 25 }

  condition:
    any of them
}