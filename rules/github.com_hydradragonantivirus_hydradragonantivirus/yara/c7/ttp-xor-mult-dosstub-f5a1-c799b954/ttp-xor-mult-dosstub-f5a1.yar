rule TTP_XOR_MULT_DOSStub_f5a1 {
  strings:
    $key_f5a1 = { a1 c9 [2] d5 d1 [2] 92 d3 [2] d5 c2 [2] 9b ce [2] 97 c4 [2] 80 cf [2] 9b 81 [2] a6 }

  condition:
    any of them
}