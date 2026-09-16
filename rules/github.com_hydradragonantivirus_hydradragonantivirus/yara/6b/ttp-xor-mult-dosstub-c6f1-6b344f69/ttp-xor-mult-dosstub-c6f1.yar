rule TTP_XOR_MULT_DOSStub_c6f1 {
  strings:
    $key_c6f1 = { 92 99 [2] e6 81 [2] a1 83 [2] e6 92 [2] a8 9e [2] a4 94 [2] b3 9f [2] a8 d1 [2] 95 }

  condition:
    any of them
}