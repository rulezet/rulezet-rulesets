rule TTP_XOR_MULT_DOSStub_79b0 {
  strings:
    $key_79b0 = { 2d d8 [2] 59 c0 [2] 1e c2 [2] 59 d3 [2] 17 df [2] 1b d5 [2] 0c de [2] 17 90 [2] 2a }

  condition:
    any of them
}