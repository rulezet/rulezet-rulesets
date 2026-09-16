rule TTP_XOR_MULT_DOSStub_b494 {
  strings:
    $key_b494 = { e0 fc [2] 94 e4 [2] d3 e6 [2] 94 f7 [2] da fb [2] d6 f1 [2] c1 fa [2] da b4 [2] e7 }

  condition:
    any of them
}