rule TTP_XOR_MULT_DOSStub_1fc9 {
  strings:
    $key_1fc9 = { 4b a1 [2] 3f b9 [2] 78 bb [2] 3f aa [2] 71 a6 [2] 7d ac [2] 6a a7 [2] 71 e9 [2] 4c }

  condition:
    any of them
}