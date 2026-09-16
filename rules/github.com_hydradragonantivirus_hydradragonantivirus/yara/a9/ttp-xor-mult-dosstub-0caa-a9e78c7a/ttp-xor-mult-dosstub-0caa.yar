rule TTP_XOR_MULT_DOSStub_0caa {
  strings:
    $key_0caa = { 58 c2 [2] 2c da [2] 6b d8 [2] 2c c9 [2] 62 c5 [2] 6e cf [2] 79 c4 [2] 62 8a [2] 5f }

  condition:
    any of them
}