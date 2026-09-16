rule TTP_XOR_MULT_DOSStub_a68b {
  strings:
    $key_a68b = { f2 e3 [2] 86 fb [2] c1 f9 [2] 86 e8 [2] c8 e4 [2] c4 ee [2] d3 e5 [2] c8 ab [2] f5 }

  condition:
    any of them
}