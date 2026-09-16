rule TTP_XOR_MULT_DOSStub_3bd4 {
  strings:
    $key_3bd4 = { 6f bc [2] 1b a4 [2] 5c a6 [2] 1b b7 [2] 55 bb [2] 59 b1 [2] 4e ba [2] 55 f4 [2] 68 }

  condition:
    any of them
}