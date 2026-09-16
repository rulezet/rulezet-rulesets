rule TTP_XOR_MULT_DOSStub_51d8 {
  strings:
    $key_51d8 = { 05 b0 [2] 71 a8 [2] 36 aa [2] 71 bb [2] 3f b7 [2] 33 bd [2] 24 b6 [2] 3f f8 [2] 02 }

  condition:
    any of them
}