rule TTP_XOR_MULT_DOSStub_3ba6 {
  strings:
    $key_3ba6 = { 6f ce [2] 1b d6 [2] 5c d4 [2] 1b c5 [2] 55 c9 [2] 59 c3 [2] 4e c8 [2] 55 86 [2] 68 }

  condition:
    any of them
}