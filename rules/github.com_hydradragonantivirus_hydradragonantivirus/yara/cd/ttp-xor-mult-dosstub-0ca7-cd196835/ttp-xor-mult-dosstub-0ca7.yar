rule TTP_XOR_MULT_DOSStub_0ca7 {
  strings:
    $key_0ca7 = { 58 cf [2] 2c d7 [2] 6b d5 [2] 2c c4 [2] 62 c8 [2] 6e c2 [2] 79 c9 [2] 62 87 [2] 5f }

  condition:
    any of them
}