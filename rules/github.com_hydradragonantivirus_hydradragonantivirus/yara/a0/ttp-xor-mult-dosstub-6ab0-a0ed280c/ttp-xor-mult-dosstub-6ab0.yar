rule TTP_XOR_MULT_DOSStub_6ab0 {
  strings:
    $key_6ab0 = { 3e d8 [2] 4a c0 [2] 0d c2 [2] 4a d3 [2] 04 df [2] 08 d5 [2] 1f de [2] 04 90 [2] 39 }

  condition:
    any of them
}