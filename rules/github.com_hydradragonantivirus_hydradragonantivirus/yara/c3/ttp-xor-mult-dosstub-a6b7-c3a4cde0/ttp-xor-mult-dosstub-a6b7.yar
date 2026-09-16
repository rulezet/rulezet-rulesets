rule TTP_XOR_MULT_DOSStub_a6b7 {
  strings:
    $key_a6b7 = { f2 df [2] 86 c7 [2] c1 c5 [2] 86 d4 [2] c8 d8 [2] c4 d2 [2] d3 d9 [2] c8 97 [2] f5 }

  condition:
    any of them
}