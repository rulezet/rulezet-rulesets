rule TTP_XOR_MULT_DOSStub_2fc9 {
  strings:
    $key_2fc9 = { 7b a1 [2] 0f b9 [2] 48 bb [2] 0f aa [2] 41 a6 [2] 4d ac [2] 5a a7 [2] 41 e9 [2] 7c }

  condition:
    any of them
}