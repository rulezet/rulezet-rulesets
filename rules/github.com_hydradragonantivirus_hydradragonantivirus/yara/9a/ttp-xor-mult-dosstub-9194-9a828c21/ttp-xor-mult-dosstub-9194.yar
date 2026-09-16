rule TTP_XOR_MULT_DOSStub_9194 {
  strings:
    $key_9194 = { c5 fc [2] b1 e4 [2] f6 e6 [2] b1 f7 [2] ff fb [2] f3 f1 [2] e4 fa [2] ff b4 [2] c2 }

  condition:
    any of them
}