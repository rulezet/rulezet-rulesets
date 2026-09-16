rule TTP_XOR_MULT_DOSStub_69b0 {
  strings:
    $key_69b0 = { 3d d8 [2] 49 c0 [2] 0e c2 [2] 49 d3 [2] 07 df [2] 0b d5 [2] 1c de [2] 07 90 [2] 3a }

  condition:
    any of them
}