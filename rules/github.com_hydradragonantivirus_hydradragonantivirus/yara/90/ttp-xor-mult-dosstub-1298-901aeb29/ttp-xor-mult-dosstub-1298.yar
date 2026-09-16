rule TTP_XOR_MULT_DOSStub_1298 {
  strings:
    $key_1298 = { 46 f0 [2] 32 e8 [2] 75 ea [2] 32 fb [2] 7c f7 [2] 70 fd [2] 67 f6 [2] 7c b8 [2] 41 }

  condition:
    any of them
}