rule TTP_XOR_MULT_DOSStub_f5d8 {
  strings:
    $key_f5d8 = { a1 b0 [2] d5 a8 [2] 92 aa [2] d5 bb [2] 9b b7 [2] 97 bd [2] 80 b6 [2] 9b f8 [2] a6 }

  condition:
    any of them
}