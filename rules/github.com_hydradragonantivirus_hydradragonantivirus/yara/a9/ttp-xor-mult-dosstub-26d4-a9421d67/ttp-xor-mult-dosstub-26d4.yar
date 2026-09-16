rule TTP_XOR_MULT_DOSStub_26d4 {
  strings:
    $key_26d4 = { 72 bc [2] 06 a4 [2] 41 a6 [2] 06 b7 [2] 48 bb [2] 44 b1 [2] 53 ba [2] 48 f4 [2] 75 }

  condition:
    any of them
}