rule TTP_XOR_MULT_DOSStub_1db0 {
  strings:
    $key_1db0 = { 49 d8 [2] 3d c0 [2] 7a c2 [2] 3d d3 [2] 73 df [2] 7f d5 [2] 68 de [2] 73 90 [2] 4e }

  condition:
    any of them
}