rule TTP_XOR_MULT_DOSStub_75d5 {
  strings:
    $key_75d5 = { 21 bd [2] 55 a5 [2] 12 a7 [2] 55 b6 [2] 1b ba [2] 17 b0 [2] 00 bb [2] 1b f5 [2] 26 }

  condition:
    any of them
}