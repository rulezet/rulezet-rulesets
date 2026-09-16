rule TTP_XOR_MULT_DOSStub_26d5 {
  strings:
    $key_26d5 = { 72 bd [2] 06 a5 [2] 41 a7 [2] 06 b6 [2] 48 ba [2] 44 b0 [2] 53 bb [2] 48 f5 [2] 75 }

  condition:
    any of them
}