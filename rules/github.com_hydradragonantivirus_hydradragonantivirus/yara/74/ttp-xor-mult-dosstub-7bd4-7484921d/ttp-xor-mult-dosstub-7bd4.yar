rule TTP_XOR_MULT_DOSStub_7bd4 {
  strings:
    $key_7bd4 = { 2f bc [2] 5b a4 [2] 1c a6 [2] 5b b7 [2] 15 bb [2] 19 b1 [2] 0e ba [2] 15 f4 [2] 28 }

  condition:
    any of them
}