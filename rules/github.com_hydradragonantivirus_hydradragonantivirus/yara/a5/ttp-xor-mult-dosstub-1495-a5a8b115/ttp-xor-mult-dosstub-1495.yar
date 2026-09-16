rule TTP_XOR_MULT_DOSStub_1495 {
  strings:
    $key_1495 = { 40 fd [2] 34 e5 [2] 73 e7 [2] 34 f6 [2] 7a fa [2] 76 f0 [2] 61 fb [2] 7a b5 [2] 47 }

  condition:
    any of them
}