rule TTP_XOR_MULT_DOSStub_aeb0 {
  strings:
    $key_aeb0 = { fa d8 [2] 8e c0 [2] c9 c2 [2] 8e d3 [2] c0 df [2] cc d5 [2] db de [2] c0 90 [2] fd }

  condition:
    any of them
}