rule TTP_XOR_MULT_DOSStub_6cb0 {
  strings:
    $key_6cb0 = { 38 d8 [2] 4c c0 [2] 0b c2 [2] 4c d3 [2] 02 df [2] 0e d5 [2] 19 de [2] 02 90 [2] 3f }

  condition:
    any of them
}