rule TTP_XOR_MULT_DOSStub_3595 {
  strings:
    $key_3595 = { 61 fd [2] 15 e5 [2] 52 e7 [2] 15 f6 [2] 5b fa [2] 57 f0 [2] 40 fb [2] 5b b5 [2] 66 }

  condition:
    any of them
}