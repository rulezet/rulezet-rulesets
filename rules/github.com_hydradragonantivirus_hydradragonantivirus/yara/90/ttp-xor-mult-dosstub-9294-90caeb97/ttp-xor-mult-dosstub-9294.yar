rule TTP_XOR_MULT_DOSStub_9294 {
  strings:
    $key_9294 = { c6 fc [2] b2 e4 [2] f5 e6 [2] b2 f7 [2] fc fb [2] f0 f1 [2] e7 fa [2] fc b4 [2] c1 }

  condition:
    any of them
}