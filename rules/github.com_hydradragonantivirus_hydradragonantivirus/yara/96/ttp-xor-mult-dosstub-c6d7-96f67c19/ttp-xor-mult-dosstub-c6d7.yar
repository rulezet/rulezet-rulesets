rule TTP_XOR_MULT_DOSStub_c6d7 {
  strings:
    $key_c6d7 = { 92 bf [2] e6 a7 [2] a1 a5 [2] e6 b4 [2] a8 b8 [2] a4 b2 [2] b3 b9 [2] a8 f7 [2] 95 }

  condition:
    any of them
}