rule TTP_XOR_MULT_DOSStub_9788 {
  strings:
    $key_9788 = { c3 e0 [2] b7 f8 [2] f0 fa [2] b7 eb [2] f9 e7 [2] f5 ed [2] e2 e6 [2] f9 a8 [2] c4 }

  condition:
    any of them
}