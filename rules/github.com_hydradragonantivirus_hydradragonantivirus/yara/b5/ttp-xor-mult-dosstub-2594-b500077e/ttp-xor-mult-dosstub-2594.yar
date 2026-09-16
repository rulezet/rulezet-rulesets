rule TTP_XOR_MULT_DOSStub_2594 {
  strings:
    $key_2594 = { 71 fc [2] 05 e4 [2] 42 e6 [2] 05 f7 [2] 4b fb [2] 47 f1 [2] 50 fa [2] 4b b4 [2] 76 }

  condition:
    any of them
}