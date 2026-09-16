rule TTP_XOR_MULT_DOSStub_c0c6 {
  strings:
    $key_c0c6 = { 94 ae [2] e0 b6 [2] a7 b4 [2] e0 a5 [2] ae a9 [2] a2 a3 [2] b5 a8 [2] ae e6 [2] 93 }

  condition:
    any of them
}