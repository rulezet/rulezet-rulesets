rule TTP_XOR_MULT_DOSStub_0ab0 {
  strings:
    $key_0ab0 = { 5e d8 [2] 2a c0 [2] 6d c2 [2] 2a d3 [2] 64 df [2] 68 d5 [2] 7f de [2] 64 90 [2] 59 }

  condition:
    any of them
}