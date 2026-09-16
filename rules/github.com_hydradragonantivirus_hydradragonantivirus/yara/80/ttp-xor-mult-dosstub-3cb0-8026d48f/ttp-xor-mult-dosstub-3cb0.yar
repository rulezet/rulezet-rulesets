rule TTP_XOR_MULT_DOSStub_3cb0 {
  strings:
    $key_3cb0 = { 68 d8 [2] 1c c0 [2] 5b c2 [2] 1c d3 [2] 52 df [2] 5e d5 [2] 49 de [2] 52 90 [2] 6f }

  condition:
    any of them
}