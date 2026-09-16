rule TTP_XOR_MULT_DOSStub_1dd0 {
  strings:
    $key_1dd0 = { 49 b8 [2] 3d a0 [2] 7a a2 [2] 3d b3 [2] 73 bf [2] 7f b5 [2] 68 be [2] 73 f0 [2] 4e }

  condition:
    any of them
}