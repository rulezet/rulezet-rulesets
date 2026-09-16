rule TTP_XOR_MULT_DOSStub_0ba6 {
  strings:
    $key_0ba6 = { 5f ce [2] 2b d6 [2] 6c d4 [2] 2b c5 [2] 65 c9 [2] 69 c3 [2] 7e c8 [2] 65 86 [2] 58 }

  condition:
    any of them
}