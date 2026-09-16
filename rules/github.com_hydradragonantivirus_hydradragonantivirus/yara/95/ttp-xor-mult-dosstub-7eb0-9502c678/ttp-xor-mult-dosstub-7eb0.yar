rule TTP_XOR_MULT_DOSStub_7eb0 {
  strings:
    $key_7eb0 = { 2a d8 [2] 5e c0 [2] 19 c2 [2] 5e d3 [2] 10 df [2] 1c d5 [2] 0b de [2] 10 90 [2] 2d }

  condition:
    any of them
}