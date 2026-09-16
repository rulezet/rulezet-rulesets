rule TTP_XOR_MULT_DOSStub_c193 {
  strings:
    $key_c193 = { 95 fb [2] e1 e3 [2] a6 e1 [2] e1 f0 [2] af fc [2] a3 f6 [2] b4 fd [2] af b3 [2] 92 }

  condition:
    any of them
}