rule TTP_XOR_MULT_DOSStub_1eb0 {
  strings:
    $key_1eb0 = { 4a d8 [2] 3e c0 [2] 79 c2 [2] 3e d3 [2] 70 df [2] 7c d5 [2] 6b de [2] 70 90 [2] 4d }

  condition:
    any of them
}