rule TTP_XOR_MULT_DOSStub_f9ac {
  strings:
    $key_f9ac = { ad c4 [2] d9 dc [2] 9e de [2] d9 cf [2] 97 c3 [2] 9b c9 [2] 8c c2 [2] 97 8c [2] aa }

  condition:
    any of them
}