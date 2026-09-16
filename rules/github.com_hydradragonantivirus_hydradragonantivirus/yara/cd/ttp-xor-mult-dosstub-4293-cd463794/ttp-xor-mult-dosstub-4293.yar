rule TTP_XOR_MULT_DOSStub_4293 {
  strings:
    $key_4293 = { 16 fb [2] 62 e3 [2] 25 e1 [2] 62 f0 [2] 2c fc [2] 20 f6 [2] 37 fd [2] 2c b3 [2] 11 }

  condition:
    any of them
}