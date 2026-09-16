rule TTP_XOR_MULT_DOSStub_66d8 {
  strings:
    $key_66d8 = { 32 b0 [2] 46 a8 [2] 01 aa [2] 46 bb [2] 08 b7 [2] 04 bd [2] 13 b6 [2] 08 f8 [2] 35 }

  condition:
    any of them
}