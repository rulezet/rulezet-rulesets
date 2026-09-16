rule TTP_XOR_MULT_DOSStub_f4d5 {
  strings:
    $key_f4d5 = { a0 bd [2] d4 a5 [2] 93 a7 [2] d4 b6 [2] 9a ba [2] 96 b0 [2] 81 bb [2] 9a f5 [2] a7 }

  condition:
    any of them
}