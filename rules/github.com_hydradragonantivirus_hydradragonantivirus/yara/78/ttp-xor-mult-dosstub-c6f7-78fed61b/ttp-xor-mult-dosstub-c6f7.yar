rule TTP_XOR_MULT_DOSStub_c6f7 {
  strings:
    $key_c6f7 = { 92 9f [2] e6 87 [2] a1 85 [2] e6 94 [2] a8 98 [2] a4 92 [2] b3 99 [2] a8 d7 [2] 95 }

  condition:
    any of them
}