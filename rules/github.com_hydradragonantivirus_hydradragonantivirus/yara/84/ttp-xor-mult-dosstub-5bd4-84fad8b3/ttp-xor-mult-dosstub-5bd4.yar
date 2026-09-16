rule TTP_XOR_MULT_DOSStub_5bd4 {
  strings:
    $key_5bd4 = { 0f bc [2] 7b a4 [2] 3c a6 [2] 7b b7 [2] 35 bb [2] 39 b1 [2] 2e ba [2] 35 f4 [2] 08 }

  condition:
    any of them
}