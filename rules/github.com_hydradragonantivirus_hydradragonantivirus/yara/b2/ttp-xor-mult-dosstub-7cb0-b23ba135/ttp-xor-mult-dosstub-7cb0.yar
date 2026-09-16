rule TTP_XOR_MULT_DOSStub_7cb0 {
  strings:
    $key_7cb0 = { 28 d8 [2] 5c c0 [2] 1b c2 [2] 5c d3 [2] 12 df [2] 1e d5 [2] 09 de [2] 12 90 [2] 2f }

  condition:
    any of them
}