rule TTP_XOR_MULT_DOSStub_7293 {
  strings:
    $key_7293 = { 26 fb [2] 52 e3 [2] 15 e1 [2] 52 f0 [2] 1c fc [2] 10 f6 [2] 07 fd [2] 1c b3 [2] 21 }

  condition:
    any of them
}