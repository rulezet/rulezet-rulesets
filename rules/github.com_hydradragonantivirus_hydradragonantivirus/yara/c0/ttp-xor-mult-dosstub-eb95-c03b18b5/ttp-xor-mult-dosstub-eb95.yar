rule TTP_XOR_MULT_DOSStub_eb95 {
  strings:
    $key_eb95 = { bf fd [2] cb e5 [2] 8c e7 [2] cb f6 [2] 85 fa [2] 89 f0 [2] 9e fb [2] 85 b5 [2] b8 }

  condition:
    any of them
}