rule TTP_XOR_MULT_DOSStub_41d8 {
  strings:
    $key_41d8 = { 15 b0 [2] 61 a8 [2] 26 aa [2] 61 bb [2] 2f b7 [2] 23 bd [2] 34 b6 [2] 2f f8 [2] 12 }

  condition:
    any of them
}