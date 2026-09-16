rule TTP_XOR_MULT_DOSStub_3594 {
  strings:
    $key_3594 = { 61 fc [2] 15 e4 [2] 52 e6 [2] 15 f7 [2] 5b fb [2] 57 f1 [2] 40 fa [2] 5b b4 [2] 66 }

  condition:
    any of them
}