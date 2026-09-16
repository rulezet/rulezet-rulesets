rule TTP_XOR_MULT_DOSStub_6bd4 {
  strings:
    $key_6bd4 = { 3f bc [2] 4b a4 [2] 0c a6 [2] 4b b7 [2] 05 bb [2] 09 b1 [2] 1e ba [2] 05 f4 [2] 38 }

  condition:
    any of them
}