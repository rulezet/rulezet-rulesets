rule TTP_XOR_MULT_DOSStub_1293 {
  strings:
    $key_1293 = { 46 fb [2] 32 e3 [2] 75 e1 [2] 32 f0 [2] 7c fc [2] 70 f6 [2] 67 fd [2] 7c b3 [2] 41 }

  condition:
    any of them
}