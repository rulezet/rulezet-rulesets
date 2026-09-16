rule TTP_XOR_MULT_DOSStub_66d4 {
  strings:
    $key_66d4 = { 32 bc [2] 46 a4 [2] 01 a6 [2] 46 b7 [2] 08 bb [2] 04 b1 [2] 13 ba [2] 08 f4 [2] 35 }

  condition:
    any of them
}