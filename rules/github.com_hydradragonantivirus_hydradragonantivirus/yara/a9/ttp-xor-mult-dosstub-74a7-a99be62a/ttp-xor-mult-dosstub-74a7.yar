rule TTP_XOR_MULT_DOSStub_74a7 {
  strings:
    $key_74a7 = { 20 cf [2] 54 d7 [2] 13 d5 [2] 54 c4 [2] 1a c8 [2] 16 c2 [2] 01 c9 [2] 1a 87 [2] 27 }

  condition:
    any of them
}