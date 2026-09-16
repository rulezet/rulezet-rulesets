rule TTP_XOR_MULT_DOSStub_a681 {
  strings:
    $key_a681 = { f2 e9 [2] 86 f1 [2] c1 f3 [2] 86 e2 [2] c8 ee [2] c4 e4 [2] d3 ef [2] c8 a1 [2] f5 }

  condition:
    any of them
}