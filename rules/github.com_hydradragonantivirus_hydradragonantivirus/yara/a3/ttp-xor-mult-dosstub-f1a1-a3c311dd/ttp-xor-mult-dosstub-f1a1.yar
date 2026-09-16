rule TTP_XOR_MULT_DOSStub_f1a1 {
  strings:
    $key_f1a1 = { a5 c9 [2] d1 d1 [2] 96 d3 [2] d1 c2 [2] 9f ce [2] 93 c4 [2] 84 cf [2] 9f 81 [2] a2 }

  condition:
    any of them
}