rule TTP_XOR_MULT_DOSStub_8594 {
  strings:
    $key_8594 = { d1 fc [2] a5 e4 [2] e2 e6 [2] a5 f7 [2] eb fb [2] e7 f1 [2] f0 fa [2] eb b4 [2] d6 }

  condition:
    any of them
}