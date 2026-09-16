rule TTP_XOR_MULT_DOSStub_5db0 {
  strings:
    $key_5db0 = { 09 d8 [2] 7d c0 [2] 3a c2 [2] 7d d3 [2] 33 df [2] 3f d5 [2] 28 de [2] 33 90 [2] 0e }

  condition:
    any of them
}