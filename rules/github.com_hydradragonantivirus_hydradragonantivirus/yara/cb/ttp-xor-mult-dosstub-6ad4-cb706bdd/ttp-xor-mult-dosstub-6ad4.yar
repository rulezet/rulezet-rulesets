rule TTP_XOR_MULT_DOSStub_6ad4 {
  strings:
    $key_6ad4 = { 3e bc [2] 4a a4 [2] 0d a6 [2] 4a b7 [2] 04 bb [2] 08 b1 [2] 1f ba [2] 04 f4 [2] 39 }

  condition:
    any of them
}