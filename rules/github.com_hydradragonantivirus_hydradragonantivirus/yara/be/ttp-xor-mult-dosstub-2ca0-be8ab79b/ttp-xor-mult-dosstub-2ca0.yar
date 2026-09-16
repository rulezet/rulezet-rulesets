rule TTP_XOR_MULT_DOSStub_2ca0 {
  strings:
    $key_2ca0 = { 78 c8 [2] 0c d0 [2] 4b d2 [2] 0c c3 [2] 42 cf [2] 4e c5 [2] 59 ce [2] 42 80 [2] 7f }

  condition:
    any of them
}