rule TTP_XOR_MULT_DOSStub_f9a1 {
  strings:
    $key_f9a1 = { ad c9 [2] d9 d1 [2] 9e d3 [2] d9 c2 [2] 97 ce [2] 9b c4 [2] 8c cf [2] 97 81 [2] aa }

  condition:
    any of them
}