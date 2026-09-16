rule TTP_XOR_MULT_DOSStub_c198 {
  strings:
    $key_c198 = { 95 f0 [2] e1 e8 [2] a6 ea [2] e1 fb [2] af f7 [2] a3 fd [2] b4 f6 [2] af b8 [2] 92 }

  condition:
    any of them
}