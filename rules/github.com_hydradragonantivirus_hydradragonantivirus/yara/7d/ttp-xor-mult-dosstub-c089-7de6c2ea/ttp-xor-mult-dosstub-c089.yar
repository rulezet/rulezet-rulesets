rule TTP_XOR_MULT_DOSStub_c089 {
  strings:
    $key_c089 = { 94 e1 [2] e0 f9 [2] a7 fb [2] e0 ea [2] ae e6 [2] a2 ec [2] b5 e7 [2] ae a9 [2] 93 }

  condition:
    any of them
}