rule TTP_XOR_MULT_DOSStub_c195 {
  strings:
    $key_c195 = { 95 fd [2] e1 e5 [2] a6 e7 [2] e1 f6 [2] af fa [2] a3 f0 [2] b4 fb [2] af b5 [2] 92 }

  condition:
    any of them
}