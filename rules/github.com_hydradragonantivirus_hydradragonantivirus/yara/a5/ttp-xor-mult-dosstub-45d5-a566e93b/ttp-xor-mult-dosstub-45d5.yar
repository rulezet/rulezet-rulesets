rule TTP_XOR_MULT_DOSStub_45d5 {
  strings:
    $key_45d5 = { 11 bd [2] 65 a5 [2] 22 a7 [2] 65 b6 [2] 2b ba [2] 27 b0 [2] 30 bb [2] 2b f5 [2] 16 }

  condition:
    any of them
}