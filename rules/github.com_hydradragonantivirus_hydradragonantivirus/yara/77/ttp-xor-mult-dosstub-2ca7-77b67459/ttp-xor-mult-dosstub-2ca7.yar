rule TTP_XOR_MULT_DOSStub_2ca7 {
  strings:
    $key_2ca7 = { 78 cf [2] 0c d7 [2] 4b d5 [2] 0c c4 [2] 42 c8 [2] 4e c2 [2] 59 c9 [2] 42 87 [2] 7f }

  condition:
    any of them
}