rule TTP_XOR_MULT_DOSStub_7395 {
  strings:
    $key_7395 = { 27 fd [2] 53 e5 [2] 14 e7 [2] 53 f6 [2] 1d fa [2] 11 f0 [2] 06 fb [2] 1d b5 [2] 20 }

  condition:
    any of them
}