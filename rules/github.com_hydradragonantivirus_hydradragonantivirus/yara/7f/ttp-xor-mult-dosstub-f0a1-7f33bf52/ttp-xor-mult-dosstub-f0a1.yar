rule TTP_XOR_MULT_DOSStub_f0a1 {
  strings:
    $key_f0a1 = { a4 c9 [2] d0 d1 [2] 97 d3 [2] d0 c2 [2] 9e ce [2] 92 c4 [2] 85 cf [2] 9e 81 [2] a3 }

  condition:
    any of them
}