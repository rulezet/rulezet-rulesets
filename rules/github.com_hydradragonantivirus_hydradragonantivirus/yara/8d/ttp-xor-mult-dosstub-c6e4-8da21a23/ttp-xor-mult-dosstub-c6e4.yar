rule TTP_XOR_MULT_DOSStub_c6e4 {
  strings:
    $key_c6e4 = { 92 8c [2] e6 94 [2] a1 96 [2] e6 87 [2] a8 8b [2] a4 81 [2] b3 8a [2] a8 c4 [2] 95 }

  condition:
    any of them
}