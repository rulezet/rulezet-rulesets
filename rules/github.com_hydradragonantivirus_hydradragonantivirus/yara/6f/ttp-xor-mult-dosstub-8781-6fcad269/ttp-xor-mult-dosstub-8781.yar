rule TTP_XOR_MULT_DOSStub_8781 {
  strings:
    $key_8781 = { d3 e9 [2] a7 f1 [2] e0 f3 [2] a7 e2 [2] e9 ee [2] e5 e4 [2] f2 ef [2] e9 a1 [2] d4 }

  condition:
    any of them
}