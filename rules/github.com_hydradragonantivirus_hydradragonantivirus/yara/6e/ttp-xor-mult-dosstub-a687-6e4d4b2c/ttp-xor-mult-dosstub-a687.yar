rule TTP_XOR_MULT_DOSStub_a687 {
  strings:
    $key_a687 = { f2 ef [2] 86 f7 [2] c1 f5 [2] 86 e4 [2] c8 e8 [2] c4 e2 [2] d3 e9 [2] c8 a7 [2] f5 }

  condition:
    any of them
}