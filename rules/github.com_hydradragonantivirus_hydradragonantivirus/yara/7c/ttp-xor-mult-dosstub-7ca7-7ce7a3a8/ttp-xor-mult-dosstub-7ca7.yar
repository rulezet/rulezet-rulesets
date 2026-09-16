rule TTP_XOR_MULT_DOSStub_7ca7 {
  strings:
    $key_7ca7 = { 28 cf [2] 5c d7 [2] 1b d5 [2] 5c c4 [2] 12 c8 [2] 1e c2 [2] 09 c9 [2] 12 87 [2] 2f }

  condition:
    any of them
}