rule TTP_XOR_MULT_DOSStub_a181 {
  strings:
    $key_a181 = { f5 e9 [2] 81 f1 [2] c6 f3 [2] 81 e2 [2] cf ee [2] c3 e4 [2] d4 ef [2] cf a1 [2] f2 }

  condition:
    any of them
}