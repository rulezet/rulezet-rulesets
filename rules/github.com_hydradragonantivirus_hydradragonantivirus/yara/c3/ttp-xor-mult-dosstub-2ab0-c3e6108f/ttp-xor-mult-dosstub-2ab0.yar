rule TTP_XOR_MULT_DOSStub_2ab0 {
  strings:
    $key_2ab0 = { 7e d8 [2] 0a c0 [2] 4d c2 [2] 0a d3 [2] 44 df [2] 48 d5 [2] 5f de [2] 44 90 [2] 79 }

  condition:
    any of them
}