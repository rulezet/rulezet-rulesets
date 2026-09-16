rule TTP_XOR_MULT_DOSStub_3db0 {
  strings:
    $key_3db0 = { 69 d8 [2] 1d c0 [2] 5a c2 [2] 1d d3 [2] 53 df [2] 5f d5 [2] 48 de [2] 53 90 [2] 6e }

  condition:
    any of them
}