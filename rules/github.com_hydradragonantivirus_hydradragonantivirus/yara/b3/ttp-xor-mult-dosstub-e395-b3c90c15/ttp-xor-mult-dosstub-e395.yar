rule TTP_XOR_MULT_DOSStub_e395 {
  strings:
    $key_e395 = { b7 fd [2] c3 e5 [2] 84 e7 [2] c3 f6 [2] 8d fa [2] 81 f0 [2] 96 fb [2] 8d b5 [2] b0 }

  condition:
    any of them
}