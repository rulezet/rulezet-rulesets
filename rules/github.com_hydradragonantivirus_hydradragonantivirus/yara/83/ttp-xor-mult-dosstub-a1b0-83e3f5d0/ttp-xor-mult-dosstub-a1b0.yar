rule TTP_XOR_MULT_DOSStub_a1b0 {
  strings:
    $key_a1b0 = { f5 d8 [2] 81 c0 [2] c6 c2 [2] 81 d3 [2] cf df [2] c3 d5 [2] d4 de [2] cf 90 [2] f2 }

  condition:
    any of them
}