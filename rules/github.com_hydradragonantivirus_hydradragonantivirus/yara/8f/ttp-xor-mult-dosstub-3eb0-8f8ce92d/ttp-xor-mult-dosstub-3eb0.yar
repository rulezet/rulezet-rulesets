rule TTP_XOR_MULT_DOSStub_3eb0 {
  strings:
    $key_3eb0 = { 6a d8 [2] 1e c0 [2] 59 c2 [2] 1e d3 [2] 50 df [2] 5c d5 [2] 4b de [2] 50 90 [2] 6d }

  condition:
    any of them
}