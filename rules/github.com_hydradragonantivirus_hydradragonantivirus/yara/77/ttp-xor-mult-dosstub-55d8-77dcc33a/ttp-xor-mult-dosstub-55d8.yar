rule TTP_XOR_MULT_DOSStub_55d8 {
  strings:
    $key_55d8 = { 01 b0 [2] 75 a8 [2] 32 aa [2] 75 bb [2] 3b b7 [2] 37 bd [2] 20 b6 [2] 3b f8 [2] 06 }

  condition:
    any of them
}