rule TTP_XOR_MULT_DOSStub_00d8 {
  strings:
    $key_00d8 = { 54 b0 [2] 20 a8 [2] 67 aa [2] 20 bb [2] 6e b7 [2] 62 bd [2] 75 b6 [2] 6e f8 [2] 53 }

  condition:
    any of them
}