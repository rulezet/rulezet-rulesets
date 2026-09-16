rule TTP_XOR_MULT_DOSStub_e8a1 {
  strings:
    $key_e8a1 = { bc c9 [2] c8 d1 [2] 8f d3 [2] c8 c2 [2] 86 ce [2] 8a c4 [2] 9d cf [2] 86 81 [2] bb }

  condition:
    any of them
}