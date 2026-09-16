rule TTP_XOR_MULT_DOSStub_73d5 {
  strings:
    $key_73d5 = { 27 bd [2] 53 a5 [2] 14 a7 [2] 53 b6 [2] 1d ba [2] 11 b0 [2] 06 bb [2] 1d f5 [2] 20 }

  condition:
    any of them
}