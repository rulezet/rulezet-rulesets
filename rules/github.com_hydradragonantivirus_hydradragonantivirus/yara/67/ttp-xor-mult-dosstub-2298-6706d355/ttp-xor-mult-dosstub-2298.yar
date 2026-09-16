rule TTP_XOR_MULT_DOSStub_2298 {
  strings:
    $key_2298 = { 76 f0 [2] 02 e8 [2] 45 ea [2] 02 fb [2] 4c f7 [2] 40 fd [2] 57 f6 [2] 4c b8 [2] 71 }

  condition:
    any of them
}