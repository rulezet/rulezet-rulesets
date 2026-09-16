rule TTP_XOR_MULT_DOSStub_c68b {
  strings:
    $key_c68b = { 92 e3 [2] e6 fb [2] a1 f9 [2] e6 e8 [2] a8 e4 [2] a4 ee [2] b3 e5 [2] a8 ab [2] 95 }

  condition:
    any of them
}