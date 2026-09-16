rule TTP_XOR_MULT_DOSStub_1594 {
  strings:
    $key_1594 = { 41 fc [2] 35 e4 [2] 72 e6 [2] 35 f7 [2] 7b fb [2] 77 f1 [2] 60 fa [2] 7b b4 [2] 46 }

  condition:
    any of them
}