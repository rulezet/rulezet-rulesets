rule TTP_XOR_MULT_DOSStub_7ba6 {
  strings:
    $key_7ba6 = { 2f ce [2] 5b d6 [2] 1c d4 [2] 5b c5 [2] 15 c9 [2] 19 c3 [2] 0e c8 [2] 15 86 [2] 28 }

  condition:
    any of them
}