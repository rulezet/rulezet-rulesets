rule TTP_XOR_MULT_DOSStub_3ab0 {
  strings:
    $key_3ab0 = { 6e d8 [2] 1a c0 [2] 5d c2 [2] 1a d3 [2] 54 df [2] 58 d5 [2] 4f de [2] 54 90 [2] 69 }

  condition:
    any of them
}