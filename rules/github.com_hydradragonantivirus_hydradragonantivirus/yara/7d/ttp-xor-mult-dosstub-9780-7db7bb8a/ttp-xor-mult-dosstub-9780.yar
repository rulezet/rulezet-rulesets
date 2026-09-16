rule TTP_XOR_MULT_DOSStub_9780 {
  strings:
    $key_9780 = { c3 e8 [2] b7 f0 [2] f0 f2 [2] b7 e3 [2] f9 ef [2] f5 e5 [2] e2 ee [2] f9 a0 [2] c4 }

  condition:
    any of them
}