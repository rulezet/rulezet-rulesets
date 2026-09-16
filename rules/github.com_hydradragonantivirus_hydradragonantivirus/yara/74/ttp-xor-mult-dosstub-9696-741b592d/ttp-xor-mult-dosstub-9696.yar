rule TTP_XOR_MULT_DOSStub_9696 {
  strings:
    $key_9696 = { c2 fe [2] b6 e6 [2] f1 e4 [2] b6 f5 [2] f8 f9 [2] f4 f3 [2] e3 f8 [2] f8 b6 [2] c5 }

  condition:
    any of them
}