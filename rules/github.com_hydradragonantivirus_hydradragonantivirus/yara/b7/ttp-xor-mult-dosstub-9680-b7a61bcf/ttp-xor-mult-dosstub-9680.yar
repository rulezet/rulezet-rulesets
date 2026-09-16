rule TTP_XOR_MULT_DOSStub_9680 {
  strings:
    $key_9680 = { c2 e8 [2] b6 f0 [2] f1 f2 [2] b6 e3 [2] f8 ef [2] f4 e5 [2] e3 ee [2] f8 a0 [2] c5 }

  condition:
    any of them
}