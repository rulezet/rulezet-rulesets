rule TTP_XOR_MULT_DOSStub_c6a6 {
  strings:
    $key_c6a6 = { 92 ce [2] e6 d6 [2] a1 d4 [2] e6 c5 [2] a8 c9 [2] a4 c3 [2] b3 c8 [2] a8 86 [2] 95 }

  condition:
    any of them
}