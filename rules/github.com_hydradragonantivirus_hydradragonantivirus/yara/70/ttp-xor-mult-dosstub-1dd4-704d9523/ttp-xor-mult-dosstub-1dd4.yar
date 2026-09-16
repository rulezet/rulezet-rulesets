rule TTP_XOR_MULT_DOSStub_1dd4 {
  strings:
    $key_1dd4 = { 49 bc [2] 3d a4 [2] 7a a6 [2] 3d b7 [2] 73 bb [2] 7f b1 [2] 68 ba [2] 73 f4 [2] 4e }

  condition:
    any of them
}