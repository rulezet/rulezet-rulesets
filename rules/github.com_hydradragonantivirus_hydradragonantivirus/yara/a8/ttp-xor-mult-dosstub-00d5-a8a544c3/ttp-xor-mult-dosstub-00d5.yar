rule TTP_XOR_MULT_DOSStub_00d5 {
  strings:
    $key_00d5 = { 54 bd [2] 20 a5 [2] 67 a7 [2] 20 b6 [2] 6e ba [2] 62 b0 [2] 75 bb [2] 6e f5 [2] 53 }

  condition:
    any of them
}