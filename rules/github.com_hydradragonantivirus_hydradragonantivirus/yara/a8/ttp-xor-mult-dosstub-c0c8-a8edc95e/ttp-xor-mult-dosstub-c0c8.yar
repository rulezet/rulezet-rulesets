rule TTP_XOR_MULT_DOSStub_c0c8 {
  strings:
    $key_c0c8 = { 94 a0 [2] e0 b8 [2] a7 ba [2] e0 ab [2] ae a7 [2] a2 ad [2] b5 a6 [2] ae e8 [2] 93 }

  condition:
    any of them
}