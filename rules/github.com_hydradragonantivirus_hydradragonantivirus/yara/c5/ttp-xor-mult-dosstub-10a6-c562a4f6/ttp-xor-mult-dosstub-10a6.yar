rule TTP_XOR_MULT_DOSStub_10a6 {
  strings:
    $key_10a6 = { 44 ce [2] 30 d6 [2] 77 d4 [2] 30 c5 [2] 7e c9 [2] 72 c3 [2] 65 c8 [2] 7e 86 [2] 43 }

  condition:
    any of them
}