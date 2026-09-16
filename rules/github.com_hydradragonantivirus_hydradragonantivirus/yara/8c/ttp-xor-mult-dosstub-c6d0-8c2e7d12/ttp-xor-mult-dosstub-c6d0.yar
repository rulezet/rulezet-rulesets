rule TTP_XOR_MULT_DOSStub_c6d0 {
  strings:
    $key_c6d0 = { 92 b8 [2] e6 a0 [2] a1 a2 [2] e6 b3 [2] a8 bf [2] a4 b5 [2] b3 be [2] a8 f0 [2] 95 }

  condition:
    any of them
}