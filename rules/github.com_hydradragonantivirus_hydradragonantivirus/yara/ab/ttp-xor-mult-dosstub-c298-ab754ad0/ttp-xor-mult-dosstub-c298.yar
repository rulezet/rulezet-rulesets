rule TTP_XOR_MULT_DOSStub_c298 {
  strings:
    $key_c298 = { 96 f0 [2] e2 e8 [2] a5 ea [2] e2 fb [2] ac f7 [2] a0 fd [2] b7 f6 [2] ac b8 [2] 91 }

  condition:
    any of them
}