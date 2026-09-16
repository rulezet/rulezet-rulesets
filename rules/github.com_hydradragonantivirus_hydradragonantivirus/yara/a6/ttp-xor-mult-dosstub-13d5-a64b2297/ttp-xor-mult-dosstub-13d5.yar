rule TTP_XOR_MULT_DOSStub_13d5 {
  strings:
    $key_13d5 = { 47 bd [2] 33 a5 [2] 74 a7 [2] 33 b6 [2] 7d ba [2] 71 b0 [2] 66 bb [2] 7d f5 [2] 40 }

  condition:
    any of them
}