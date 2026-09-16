rule TTP_XOR_MULT_DOSStub_5595 {
  strings:
    $key_5595 = { 01 fd [2] 75 e5 [2] 32 e7 [2] 75 f6 [2] 3b fa [2] 37 f0 [2] 20 fb [2] 3b b5 [2] 06 }

  condition:
    any of them
}