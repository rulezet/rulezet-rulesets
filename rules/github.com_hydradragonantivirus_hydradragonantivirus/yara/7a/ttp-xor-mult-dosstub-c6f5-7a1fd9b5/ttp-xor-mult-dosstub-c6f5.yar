rule TTP_XOR_MULT_DOSStub_c6f5 {
  strings:
    $key_c6f5 = { 92 9d [2] e6 85 [2] a1 87 [2] e6 96 [2] a8 9a [2] a4 90 [2] b3 9b [2] a8 d5 [2] 95 }

  condition:
    any of them
}