rule TTP_XOR_MULT_DOSStub_0dd4 {
  strings:
    $key_0dd4 = { 59 bc [2] 2d a4 [2] 6a a6 [2] 2d b7 [2] 63 bb [2] 6f b1 [2] 78 ba [2] 63 f4 [2] 5e }

  condition:
    any of them
}