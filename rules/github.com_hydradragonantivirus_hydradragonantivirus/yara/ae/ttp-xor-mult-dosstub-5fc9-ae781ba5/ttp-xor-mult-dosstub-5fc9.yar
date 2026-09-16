rule TTP_XOR_MULT_DOSStub_5fc9 {
  strings:
    $key_5fc9 = { 0b a1 [2] 7f b9 [2] 38 bb [2] 7f aa [2] 31 a6 [2] 3d ac [2] 2a a7 [2] 31 e9 [2] 0c }

  condition:
    any of them
}