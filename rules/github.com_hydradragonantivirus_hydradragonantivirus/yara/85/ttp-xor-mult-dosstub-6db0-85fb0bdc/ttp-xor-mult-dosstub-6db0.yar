rule TTP_XOR_MULT_DOSStub_6db0 {
  strings:
    $key_6db0 = { 39 d8 [2] 4d c0 [2] 0a c2 [2] 4d d3 [2] 03 df [2] 0f d5 [2] 18 de [2] 03 90 [2] 3e }

  condition:
    any of them
}