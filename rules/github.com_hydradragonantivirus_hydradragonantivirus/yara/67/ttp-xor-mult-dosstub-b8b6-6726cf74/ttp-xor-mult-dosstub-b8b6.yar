rule TTP_XOR_MULT_DOSStub_b8b6 {
  strings:
    $key_b8b6 = { ec de [2] 98 c6 [2] df c4 [2] 98 d5 [2] d6 d9 [2] da d3 [2] cd d8 [2] d6 96 [2] eb }

  condition:
    any of them
}