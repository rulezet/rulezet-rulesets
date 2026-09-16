rule TTP_XOR_MULT_DOSStub_c0c3 {
  strings:
    $key_c0c3 = { 94 ab [2] e0 b3 [2] a7 b1 [2] e0 a0 [2] ae ac [2] a2 a6 [2] b5 ad [2] ae e3 [2] 93 }

  condition:
    any of them
}