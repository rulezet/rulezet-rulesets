rule TTP_XOR_MULT_DOSStub_f4a1 {
  strings:
    $key_f4a1 = { a0 c9 [2] d4 d1 [2] 93 d3 [2] d4 c2 [2] 9a ce [2] 96 c4 [2] 81 cf [2] 9a 81 [2] a7 }

  condition:
    any of them
}