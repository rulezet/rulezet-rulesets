rule TTP_XOR_MULT_DOSStub_24d5 {
  strings:
    $key_24d5 = { 70 bd [2] 04 a5 [2] 43 a7 [2] 04 b6 [2] 4a ba [2] 46 b0 [2] 51 bb [2] 4a f5 [2] 77 }

  condition:
    any of them
}