rule TTP_XOR_MULT_DOSStub_51d5 {
  strings:
    $key_51d5 = { 05 bd [2] 71 a5 [2] 36 a7 [2] 71 b6 [2] 3f ba [2] 33 b0 [2] 24 bb [2] 3f f5 [2] 02 }

  condition:
    any of them
}