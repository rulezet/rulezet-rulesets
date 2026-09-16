rule TTP_XOR_MULT_DOSStub_1bb0 {
  strings:
    $key_1bb0 = { 4f d8 [2] 3b c0 [2] 7c c2 [2] 3b d3 [2] 75 df [2] 79 d5 [2] 6e de [2] 75 90 [2] 48 }

  condition:
    any of them
}