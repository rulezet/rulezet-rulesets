rule TTP_XOR_MULT_DOSStub_2cb0 {
  strings:
    $key_2cb0 = { 78 d8 [2] 0c c0 [2] 4b c2 [2] 0c d3 [2] 42 df [2] 4e d5 [2] 59 de [2] 42 90 [2] 7f }

  condition:
    any of them
}