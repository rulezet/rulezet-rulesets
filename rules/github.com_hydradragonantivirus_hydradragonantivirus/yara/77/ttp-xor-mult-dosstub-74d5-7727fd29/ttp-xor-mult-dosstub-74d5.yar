rule TTP_XOR_MULT_DOSStub_74d5 {
  strings:
    $key_74d5 = { 20 bd [2] 54 a5 [2] 13 a7 [2] 54 b6 [2] 1a ba [2] 16 b0 [2] 01 bb [2] 1a f5 [2] 27 }

  condition:
    any of them
}