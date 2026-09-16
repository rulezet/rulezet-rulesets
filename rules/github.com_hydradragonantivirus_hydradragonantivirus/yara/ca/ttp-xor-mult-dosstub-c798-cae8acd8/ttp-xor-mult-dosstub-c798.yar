rule TTP_XOR_MULT_DOSStub_c798 {
  strings:
    $key_c798 = { 93 f0 [2] e7 e8 [2] a0 ea [2] e7 fb [2] a9 f7 [2] a5 fd [2] b2 f6 [2] a9 b8 [2] 94 }

  condition:
    any of them
}