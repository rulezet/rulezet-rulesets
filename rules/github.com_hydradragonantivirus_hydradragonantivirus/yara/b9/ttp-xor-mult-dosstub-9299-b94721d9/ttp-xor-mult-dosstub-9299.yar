rule TTP_XOR_MULT_DOSStub_9299 {
  strings:
    $key_9299 = { c6 f1 [2] b2 e9 [2] f5 eb [2] b2 fa [2] fc f6 [2] f0 fc [2] e7 f7 [2] fc b9 [2] c1 }

  condition:
    any of them
}