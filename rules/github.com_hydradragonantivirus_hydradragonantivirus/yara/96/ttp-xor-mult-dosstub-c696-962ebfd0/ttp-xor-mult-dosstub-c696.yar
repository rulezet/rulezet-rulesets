rule TTP_XOR_MULT_DOSStub_c696 {
  strings:
    $key_c696 = { 92 fe [2] e6 e6 [2] a1 e4 [2] e6 f5 [2] a8 f9 [2] a4 f3 [2] b3 f8 [2] a8 b6 [2] 95 }

  condition:
    any of them
}