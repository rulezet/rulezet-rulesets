rule TTP_XOR_MULT_DOSStub_9088 {
  strings:
    $key_9088 = { c4 e0 [2] b0 f8 [2] f7 fa [2] b0 eb [2] fe e7 [2] f2 ed [2] e5 e6 [2] fe a8 [2] c3 }

  condition:
    any of them
}