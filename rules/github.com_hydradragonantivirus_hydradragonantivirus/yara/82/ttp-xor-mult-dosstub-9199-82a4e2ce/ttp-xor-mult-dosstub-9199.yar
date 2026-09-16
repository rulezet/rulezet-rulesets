rule TTP_XOR_MULT_DOSStub_9199 {
  strings:
    $key_9199 = { c5 f1 [2] b1 e9 [2] f6 eb [2] b1 fa [2] ff f6 [2] f3 fc [2] e4 f7 [2] ff b9 [2] c2 }

  condition:
    any of them
}