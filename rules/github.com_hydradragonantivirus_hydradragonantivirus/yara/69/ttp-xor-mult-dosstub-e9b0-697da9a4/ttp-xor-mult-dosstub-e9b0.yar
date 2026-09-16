rule TTP_XOR_MULT_DOSStub_e9b0 {
  strings:
    $key_e9b0 = { bd d8 [2] c9 c0 [2] 8e c2 [2] c9 d3 [2] 87 df [2] 8b d5 [2] 9c de [2] 87 90 [2] ba }

  condition:
    any of them
}