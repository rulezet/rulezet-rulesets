rule TTP_XOR_MULT_DOSStub_47a6 {
  strings:
    $key_47a6 = { 13 ce [2] 67 d6 [2] 20 d4 [2] 67 c5 [2] 29 c9 [2] 25 c3 [2] 32 c8 [2] 29 86 [2] 14 }

  condition:
    any of them
}