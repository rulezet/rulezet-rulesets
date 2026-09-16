rule TTP_XOR_MULT_DOSStub_a194 {
  strings:
    $key_a194 = { f5 fc [2] 81 e4 [2] c6 e6 [2] 81 f7 [2] cf fb [2] c3 f1 [2] d4 fa [2] cf b4 [2] f2 }

  condition:
    any of them
}