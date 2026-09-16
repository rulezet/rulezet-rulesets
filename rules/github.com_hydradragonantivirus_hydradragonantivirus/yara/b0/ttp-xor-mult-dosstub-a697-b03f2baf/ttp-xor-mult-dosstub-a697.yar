rule TTP_XOR_MULT_DOSStub_a697 {
  strings:
    $key_a697 = { f2 ff [2] 86 e7 [2] c1 e5 [2] 86 f4 [2] c8 f8 [2] c4 f2 [2] d3 f9 [2] c8 b7 [2] f5 }

  condition:
    any of them
}