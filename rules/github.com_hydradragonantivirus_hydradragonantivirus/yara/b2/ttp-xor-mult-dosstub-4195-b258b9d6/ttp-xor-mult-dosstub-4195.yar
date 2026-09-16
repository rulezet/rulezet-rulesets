rule TTP_XOR_MULT_DOSStub_4195 {
  strings:
    $key_4195 = { 15 fd [2] 61 e5 [2] 26 e7 [2] 61 f6 [2] 2f fa [2] 23 f0 [2] 34 fb [2] 2f b5 [2] 12 }

  condition:
    any of them
}