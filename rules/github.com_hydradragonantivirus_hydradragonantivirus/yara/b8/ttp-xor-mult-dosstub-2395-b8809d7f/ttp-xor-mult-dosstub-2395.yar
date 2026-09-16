rule TTP_XOR_MULT_DOSStub_2395 {
  strings:
    $key_2395 = { 77 fd [2] 03 e5 [2] 44 e7 [2] 03 f6 [2] 4d fa [2] 41 f0 [2] 56 fb [2] 4d b5 [2] 70 }

  condition:
    any of them
}