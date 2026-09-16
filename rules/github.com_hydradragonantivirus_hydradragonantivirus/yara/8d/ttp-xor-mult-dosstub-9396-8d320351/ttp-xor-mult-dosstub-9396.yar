rule TTP_XOR_MULT_DOSStub_9396 {
  strings:
    $key_9396 = { c7 fe [2] b3 e6 [2] f4 e4 [2] b3 f5 [2] fd f9 [2] f1 f3 [2] e6 f8 [2] fd b6 [2] c0 }

  condition:
    any of them
}