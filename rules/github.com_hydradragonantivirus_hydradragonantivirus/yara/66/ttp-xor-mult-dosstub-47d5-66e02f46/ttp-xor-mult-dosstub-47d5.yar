rule TTP_XOR_MULT_DOSStub_47d5 {
  strings:
    $key_47d5 = { 13 bd [2] 67 a5 [2] 20 a7 [2] 67 b6 [2] 29 ba [2] 25 b0 [2] 32 bb [2] 29 f5 [2] 14 }

  condition:
    any of them
}