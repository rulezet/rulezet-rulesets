rule TTP_XOR_MULT_DOSStub_3fc9 {
  strings:
    $key_3fc9 = { 6b a1 [2] 1f b9 [2] 58 bb [2] 1f aa [2] 51 a6 [2] 5d ac [2] 4a a7 [2] 51 e9 [2] 6c }

  condition:
    any of them
}