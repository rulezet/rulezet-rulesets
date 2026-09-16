rule TTP_XOR_MULT_DOSStub_50a6 {
  strings:
    $key_50a6 = { 04 ce [2] 70 d6 [2] 37 d4 [2] 70 c5 [2] 3e c9 [2] 32 c3 [2] 25 c8 [2] 3e 86 [2] 03 }

  condition:
    any of them
}