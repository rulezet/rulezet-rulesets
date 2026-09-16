rule TTP_XOR_MULT_DOSStub_1dd3 {
  strings:
    $key_1dd3 = { 49 bb [2] 3d a3 [2] 7a a1 [2] 3d b0 [2] 73 bc [2] 7f b6 [2] 68 bd [2] 73 f3 [2] 4e }

  condition:
    any of them
}