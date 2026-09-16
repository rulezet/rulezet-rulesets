rule TTP_XOR_MULT_DOSStub_ac95 {
  strings:
    $key_ac95 = { f8 fd [2] 8c e5 [2] cb e7 [2] 8c f6 [2] c2 fa [2] ce f0 [2] d9 fb [2] c2 b5 [2] ff }

  condition:
    any of them
}