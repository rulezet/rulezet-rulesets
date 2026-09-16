rule TTP_XOR_MULT_DOSStub_7594 {
  strings:
    $key_7594 = { 21 fc [2] 55 e4 [2] 12 e6 [2] 55 f7 [2] 1b fb [2] 17 f1 [2] 00 fa [2] 1b b4 [2] 26 }

  condition:
    any of them
}