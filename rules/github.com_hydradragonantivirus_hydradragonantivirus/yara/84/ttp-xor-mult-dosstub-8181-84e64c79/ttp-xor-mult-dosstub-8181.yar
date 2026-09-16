rule TTP_XOR_MULT_DOSStub_8181 {
  strings:
    $key_8181 = { d5 e9 [2] a1 f1 [2] e6 f3 [2] a1 e2 [2] ef ee [2] e3 e4 [2] f4 ef [2] ef a1 [2] d2 }

  condition:
    any of them
}