rule TTP_XOR_MULT_DOSStub_c6e6 {
  strings:
    $key_c6e6 = { 92 8e [2] e6 96 [2] a1 94 [2] e6 85 [2] a8 89 [2] a4 83 [2] b3 88 [2] a8 c6 [2] 95 }

  condition:
    any of them
}