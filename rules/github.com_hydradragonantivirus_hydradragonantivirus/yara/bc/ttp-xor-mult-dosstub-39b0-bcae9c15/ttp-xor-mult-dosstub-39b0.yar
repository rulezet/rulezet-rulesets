rule TTP_XOR_MULT_DOSStub_39b0 {
  strings:
    $key_39b0 = { 6d d8 [2] 19 c0 [2] 5e c2 [2] 19 d3 [2] 57 df [2] 5b d5 [2] 4c de [2] 57 90 [2] 6a }

  condition:
    any of them
}