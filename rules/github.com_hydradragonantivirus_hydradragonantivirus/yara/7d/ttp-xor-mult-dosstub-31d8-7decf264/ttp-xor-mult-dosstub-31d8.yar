rule TTP_XOR_MULT_DOSStub_31d8 {
  strings:
    $key_31d8 = { 65 b0 [2] 11 a8 [2] 56 aa [2] 11 bb [2] 5f b7 [2] 53 bd [2] 44 b6 [2] 5f f8 [2] 62 }

  condition:
    any of them
}