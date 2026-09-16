rule TTP_XOR_MULT_DOSStub_44d5 {
  strings:
    $key_44d5 = { 10 bd [2] 64 a5 [2] 23 a7 [2] 64 b6 [2] 2a ba [2] 26 b0 [2] 31 bb [2] 2a f5 [2] 17 }

  condition:
    any of them
}