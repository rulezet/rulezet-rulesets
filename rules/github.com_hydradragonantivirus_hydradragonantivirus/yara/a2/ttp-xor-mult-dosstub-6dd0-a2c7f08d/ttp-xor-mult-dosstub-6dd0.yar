rule TTP_XOR_MULT_DOSStub_6dd0 {
  strings:
    $key_6dd0 = { 39 b8 [2] 4d a0 [2] 0a a2 [2] 4d b3 [2] 03 bf [2] 0f b5 [2] 18 be [2] 03 f0 [2] 3e }

  condition:
    any of them
}