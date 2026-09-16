rule TTP_XOR_MULT_DOSStub_63d5 {
  strings:
    $key_63d5 = { 37 bd [2] 43 a5 [2] 04 a7 [2] 43 b6 [2] 0d ba [2] 01 b0 [2] 16 bb [2] 0d f5 [2] 30 }

  condition:
    any of them
}