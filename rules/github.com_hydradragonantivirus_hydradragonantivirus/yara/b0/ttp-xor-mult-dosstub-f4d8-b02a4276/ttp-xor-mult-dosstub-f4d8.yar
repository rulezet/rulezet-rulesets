rule TTP_XOR_MULT_DOSStub_f4d8 {
  strings:
    $key_f4d8 = { a0 b0 [2] d4 a8 [2] 93 aa [2] d4 bb [2] 9a b7 [2] 96 bd [2] 81 b6 [2] 9a f8 [2] a7 }

  condition:
    any of them
}