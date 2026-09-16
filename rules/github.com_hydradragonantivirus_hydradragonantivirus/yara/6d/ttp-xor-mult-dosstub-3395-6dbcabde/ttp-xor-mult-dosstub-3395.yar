rule TTP_XOR_MULT_DOSStub_3395 {
  strings:
    $key_3395 = { 67 fd [2] 13 e5 [2] 54 e7 [2] 13 f6 [2] 5d fa [2] 51 f0 [2] 46 fb [2] 5d b5 [2] 60 }

  condition:
    any of them
}