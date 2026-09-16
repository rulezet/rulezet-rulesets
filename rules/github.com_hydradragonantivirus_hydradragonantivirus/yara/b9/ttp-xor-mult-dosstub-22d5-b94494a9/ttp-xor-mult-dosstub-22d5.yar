rule TTP_XOR_MULT_DOSStub_22d5 {
  strings:
    $key_22d5 = { 76 bd [2] 02 a5 [2] 45 a7 [2] 02 b6 [2] 4c ba [2] 40 b0 [2] 57 bb [2] 4c f5 [2] 71 }

  condition:
    any of them
}