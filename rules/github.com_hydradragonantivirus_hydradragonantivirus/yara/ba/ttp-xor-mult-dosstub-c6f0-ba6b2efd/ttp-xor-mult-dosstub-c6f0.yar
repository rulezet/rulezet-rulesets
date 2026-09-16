rule TTP_XOR_MULT_DOSStub_c6f0 {
  strings:
    $key_c6f0 = { 92 98 [2] e6 80 [2] a1 82 [2] e6 93 [2] a8 9f [2] a4 95 [2] b3 9e [2] a8 d0 [2] 95 }

  condition:
    any of them
}