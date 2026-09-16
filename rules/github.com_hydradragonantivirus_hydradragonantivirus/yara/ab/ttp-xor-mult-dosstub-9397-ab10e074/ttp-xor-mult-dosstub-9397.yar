rule TTP_XOR_MULT_DOSStub_9397 {
  strings:
    $key_9397 = { c7 ff [2] b3 e7 [2] f4 e5 [2] b3 f4 [2] fd f8 [2] f1 f2 [2] e6 f9 [2] fd b7 [2] c0 }

  condition:
    any of them
}