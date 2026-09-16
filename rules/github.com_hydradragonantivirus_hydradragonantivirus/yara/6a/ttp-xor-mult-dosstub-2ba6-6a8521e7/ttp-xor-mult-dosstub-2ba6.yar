rule TTP_XOR_MULT_DOSStub_2ba6 {
  strings:
    $key_2ba6 = { 7f ce [2] 0b d6 [2] 4c d4 [2] 0b c5 [2] 45 c9 [2] 49 c3 [2] 5e c8 [2] 45 86 [2] 78 }

  condition:
    any of them
}