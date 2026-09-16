rule TTP_XOR_MULT_DOSStub_e095 {
  strings:
    $key_e095 = { b4 fd [2] c0 e5 [2] 87 e7 [2] c0 f6 [2] 8e fa [2] 82 f0 [2] 95 fb [2] 8e b5 [2] b3 }

  condition:
    any of them
}