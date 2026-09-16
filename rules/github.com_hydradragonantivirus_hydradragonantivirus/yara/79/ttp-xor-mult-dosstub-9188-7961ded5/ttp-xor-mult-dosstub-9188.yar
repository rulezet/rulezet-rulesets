rule TTP_XOR_MULT_DOSStub_9188 {
  strings:
    $key_9188 = { c5 e0 [2] b1 f8 [2] f6 fa [2] b1 eb [2] ff e7 [2] f3 ed [2] e4 e6 [2] ff a8 [2] c2 }

  condition:
    any of them
}