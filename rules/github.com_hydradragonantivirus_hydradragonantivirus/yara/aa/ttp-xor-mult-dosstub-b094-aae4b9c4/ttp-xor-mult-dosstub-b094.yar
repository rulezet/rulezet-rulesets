rule TTP_XOR_MULT_DOSStub_b094 {
  strings:
    $key_b094 = { e4 fc [2] 90 e4 [2] d7 e6 [2] 90 f7 [2] de fb [2] d2 f1 [2] c5 fa [2] de b4 [2] e3 }

  condition:
    any of them
}