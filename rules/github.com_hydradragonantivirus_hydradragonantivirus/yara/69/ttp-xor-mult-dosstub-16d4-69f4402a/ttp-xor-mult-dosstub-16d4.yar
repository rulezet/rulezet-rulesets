rule TTP_XOR_MULT_DOSStub_16d4 {
  strings:
    $key_16d4 = { 42 bc [2] 36 a4 [2] 71 a6 [2] 36 b7 [2] 78 bb [2] 74 b1 [2] 63 ba [2] 78 f4 [2] 45 }

  condition:
    any of them
}