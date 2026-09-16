rule TTP_XOR_MULT_DOSStub_60a6 {
  strings:
    $key_60a6 = { 34 ce [2] 40 d6 [2] 07 d4 [2] 40 c5 [2] 0e c9 [2] 02 c3 [2] 15 c8 [2] 0e 86 [2] 33 }

  condition:
    any of them
}