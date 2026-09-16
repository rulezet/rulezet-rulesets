rule TTP_XOR_MULT_DOSStub_3ad4 {
  strings:
    $key_3ad4 = { 6e bc [2] 1a a4 [2] 5d a6 [2] 1a b7 [2] 54 bb [2] 58 b1 [2] 4f ba [2] 54 f4 [2] 69 }

  condition:
    any of them
}