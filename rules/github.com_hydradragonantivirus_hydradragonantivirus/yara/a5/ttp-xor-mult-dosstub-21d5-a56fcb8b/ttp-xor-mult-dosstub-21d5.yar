rule TTP_XOR_MULT_DOSStub_21d5 {
  strings:
    $key_21d5 = { 75 bd [2] 01 a5 [2] 46 a7 [2] 01 b6 [2] 4f ba [2] 43 b0 [2] 54 bb [2] 4f f5 [2] 72 }

  condition:
    any of them
}