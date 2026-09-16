rule TTP_XOR_MULT_DOSStub_9094 {
  strings:
    $key_9094 = { c4 fc [2] b0 e4 [2] f7 e6 [2] b0 f7 [2] fe fb [2] f2 f1 [2] e5 fa [2] fe b4 [2] c3 }

  condition:
    any of them
}