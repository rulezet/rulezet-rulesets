rule TTP_XOR_MULT_DOSStub_6eb0 {
  strings:
    $key_6eb0 = { 3a d8 [2] 4e c0 [2] 09 c2 [2] 4e d3 [2] 00 df [2] 0c d5 [2] 1b de [2] 00 90 [2] 3d }

  condition:
    any of them
}