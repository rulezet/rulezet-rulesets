rule TTP_XOR_MULT_DOSStub_7393 {
  strings:
    $key_7393 = { 27 fb [2] 53 e3 [2] 14 e1 [2] 53 f0 [2] 1d fc [2] 11 f6 [2] 06 fd [2] 1d b3 [2] 20 }

  condition:
    any of them
}