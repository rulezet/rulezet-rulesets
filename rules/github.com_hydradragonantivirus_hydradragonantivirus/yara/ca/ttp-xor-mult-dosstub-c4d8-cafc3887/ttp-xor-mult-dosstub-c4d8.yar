rule TTP_XOR_MULT_DOSStub_c4d8 {
  strings:
    $key_c4d8 = { 90 b0 [2] e4 a8 [2] a3 aa [2] e4 bb [2] aa b7 [2] a6 bd [2] b1 b6 [2] aa f8 [2] 97 }

  condition:
    any of them
}