rule TTP_XOR_MULT_DOSStub_71d5 {
  strings:
    $key_71d5 = { 25 bd [2] 51 a5 [2] 16 a7 [2] 51 b6 [2] 1f ba [2] 13 b0 [2] 04 bb [2] 1f f5 [2] 22 }

  condition:
    any of them
}