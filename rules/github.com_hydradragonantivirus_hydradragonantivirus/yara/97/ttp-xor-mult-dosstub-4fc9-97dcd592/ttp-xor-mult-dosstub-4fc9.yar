rule TTP_XOR_MULT_DOSStub_4fc9 {
  strings:
    $key_4fc9 = { 1b a1 [2] 6f b9 [2] 28 bb [2] 6f aa [2] 21 a6 [2] 2d ac [2] 3a a7 [2] 21 e9 [2] 1c }

  condition:
    any of them
}