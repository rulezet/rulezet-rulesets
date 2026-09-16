rule TTP_XOR_MULT_DOSStub_1ab0 {
  strings:
    $key_1ab0 = { 4e d8 [2] 3a c0 [2] 7d c2 [2] 3a d3 [2] 74 df [2] 78 d5 [2] 6f de [2] 74 90 [2] 49 }

  condition:
    any of them
}