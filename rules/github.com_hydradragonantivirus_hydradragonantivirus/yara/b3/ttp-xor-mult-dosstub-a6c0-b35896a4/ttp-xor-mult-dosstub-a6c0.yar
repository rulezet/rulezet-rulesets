rule TTP_XOR_MULT_DOSStub_a6c0 {
  strings:
    $key_a6c0 = { f2 a8 [2] 86 b0 [2] c1 b2 [2] 86 a3 [2] c8 af [2] c4 a5 [2] d3 ae [2] c8 e0 [2] f5 }

  condition:
    any of them
}