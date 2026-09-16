rule TTP_XOR_MULT_DOSStub_8681 {
  strings:
    $key_8681 = { d2 e9 [2] a6 f1 [2] e1 f3 [2] a6 e2 [2] e8 ee [2] e4 e4 [2] f3 ef [2] e8 a1 [2] d5 }

  condition:
    any of them
}