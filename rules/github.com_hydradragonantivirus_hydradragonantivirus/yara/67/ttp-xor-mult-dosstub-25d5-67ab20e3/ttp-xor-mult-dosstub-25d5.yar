rule TTP_XOR_MULT_DOSStub_25d5 {
  strings:
    $key_25d5 = { 71 bd [2] 05 a5 [2] 42 a7 [2] 05 b6 [2] 4b ba [2] 47 b0 [2] 50 bb [2] 4b f5 [2] 76 }

  condition:
    any of them
}