rule TTP_XOR_MULT_DOSStub_1ad4 {
  strings:
    $key_1ad4 = { 4e bc [2] 3a a4 [2] 7d a6 [2] 3a b7 [2] 74 bb [2] 78 b1 [2] 6f ba [2] 74 f4 [2] 49 }

  condition:
    any of them
}