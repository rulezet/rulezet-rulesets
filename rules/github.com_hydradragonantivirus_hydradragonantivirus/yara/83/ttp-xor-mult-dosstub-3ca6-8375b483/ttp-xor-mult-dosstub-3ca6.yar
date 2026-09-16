rule TTP_XOR_MULT_DOSStub_3ca6 {
  strings:
    $key_3ca6 = { 68 ce [2] 1c d6 [2] 5b d4 [2] 1c c5 [2] 52 c9 [2] 5e c3 [2] 49 c8 [2] 52 86 [2] 6f }

  condition:
    any of them
}