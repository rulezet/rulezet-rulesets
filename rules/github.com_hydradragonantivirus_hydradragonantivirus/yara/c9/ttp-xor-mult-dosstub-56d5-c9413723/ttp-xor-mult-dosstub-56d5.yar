rule TTP_XOR_MULT_DOSStub_56d5 {
  strings:
    $key_56d5 = { 02 bd [2] 76 a5 [2] 31 a7 [2] 76 b6 [2] 38 ba [2] 34 b0 [2] 23 bb [2] 38 f5 [2] 05 }

  condition:
    any of them
}