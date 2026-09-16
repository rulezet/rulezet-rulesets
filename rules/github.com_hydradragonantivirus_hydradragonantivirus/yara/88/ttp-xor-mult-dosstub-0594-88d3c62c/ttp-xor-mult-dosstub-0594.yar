rule TTP_XOR_MULT_DOSStub_0594 {
  strings:
    $key_0594 = { 51 fc [2] 25 e4 [2] 62 e6 [2] 25 f7 [2] 6b fb [2] 67 f1 [2] 70 fa [2] 6b b4 [2] 56 }

  condition:
    any of them
}