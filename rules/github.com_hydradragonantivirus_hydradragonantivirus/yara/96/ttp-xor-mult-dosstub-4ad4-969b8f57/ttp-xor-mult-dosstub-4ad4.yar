rule TTP_XOR_MULT_DOSStub_4ad4 {
  strings:
    $key_4ad4 = { 1e bc [2] 6a a4 [2] 2d a6 [2] 6a b7 [2] 24 bb [2] 28 b1 [2] 3f ba [2] 24 f4 [2] 19 }

  condition:
    any of them
}