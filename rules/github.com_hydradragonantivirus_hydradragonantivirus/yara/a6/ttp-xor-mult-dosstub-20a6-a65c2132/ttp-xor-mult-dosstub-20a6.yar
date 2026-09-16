rule TTP_XOR_MULT_DOSStub_20a6 {
  strings:
    $key_20a6 = { 74 ce [2] 00 d6 [2] 47 d4 [2] 00 c5 [2] 4e c9 [2] 42 c3 [2] 55 c8 [2] 4e 86 [2] 73 }

  condition:
    any of them
}