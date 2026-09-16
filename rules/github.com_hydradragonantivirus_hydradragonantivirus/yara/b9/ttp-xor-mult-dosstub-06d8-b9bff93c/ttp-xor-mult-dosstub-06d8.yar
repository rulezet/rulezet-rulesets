rule TTP_XOR_MULT_DOSStub_06d8 {
  strings:
    $key_06d8 = { 52 b0 [2] 26 a8 [2] 61 aa [2] 26 bb [2] 68 b7 [2] 64 bd [2] 73 b6 [2] 68 f8 [2] 55 }

  condition:
    any of them
}