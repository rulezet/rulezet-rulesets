rule TTP_XOR_MULT_DOSStub_9599 {
  strings:
    $key_9599 = { c1 f1 [2] b5 e9 [2] f2 eb [2] b5 fa [2] fb f6 [2] f7 fc [2] e0 f7 [2] fb b9 [2] c6 }

  condition:
    any of them
}