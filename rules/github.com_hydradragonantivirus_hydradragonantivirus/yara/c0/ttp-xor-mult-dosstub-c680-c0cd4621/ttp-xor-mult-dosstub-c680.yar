rule TTP_XOR_MULT_DOSStub_c680 {
  strings:
    $key_c680 = { 92 e8 [2] e6 f0 [2] a1 f2 [2] e6 e3 [2] a8 ef [2] a4 e5 [2] b3 ee [2] a8 a0 [2] 95 }

  condition:
    any of them
}