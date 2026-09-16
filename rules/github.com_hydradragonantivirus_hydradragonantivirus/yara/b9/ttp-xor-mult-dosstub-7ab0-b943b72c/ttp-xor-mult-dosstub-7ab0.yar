rule TTP_XOR_MULT_DOSStub_7ab0 {
  strings:
    $key_7ab0 = { 2e d8 [2] 5a c0 [2] 1d c2 [2] 5a d3 [2] 14 df [2] 18 d5 [2] 0f de [2] 14 90 [2] 29 }

  condition:
    any of them
}