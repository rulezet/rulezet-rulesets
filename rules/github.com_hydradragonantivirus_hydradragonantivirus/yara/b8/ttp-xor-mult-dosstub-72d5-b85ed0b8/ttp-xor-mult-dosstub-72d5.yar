rule TTP_XOR_MULT_DOSStub_72d5 {
  strings:
    $key_72d5 = { 26 bd [2] 52 a5 [2] 15 a7 [2] 52 b6 [2] 1c ba [2] 10 b0 [2] 07 bb [2] 1c f5 [2] 21 }

  condition:
    any of them
}