rule TTP_XOR_MULT_DOSStub_36d4 {
  strings:
    $key_36d4 = { 62 bc [2] 16 a4 [2] 51 a6 [2] 16 b7 [2] 58 bb [2] 54 b1 [2] 43 ba [2] 58 f4 [2] 65 }

  condition:
    any of them
}