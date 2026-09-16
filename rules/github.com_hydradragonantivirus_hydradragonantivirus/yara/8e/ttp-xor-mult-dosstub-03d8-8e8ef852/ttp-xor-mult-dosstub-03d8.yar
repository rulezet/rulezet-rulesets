rule TTP_XOR_MULT_DOSStub_03d8 {
  strings:
    $key_03d8 = { 57 b0 [2] 23 a8 [2] 64 aa [2] 23 bb [2] 6d b7 [2] 61 bd [2] 76 b6 [2] 6d f8 [2] 50 }

  condition:
    any of them
}