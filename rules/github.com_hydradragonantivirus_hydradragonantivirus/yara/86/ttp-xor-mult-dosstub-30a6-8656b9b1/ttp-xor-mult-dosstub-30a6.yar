rule TTP_XOR_MULT_DOSStub_30a6 {
  strings:
    $key_30a6 = { 64 ce [2] 10 d6 [2] 57 d4 [2] 10 c5 [2] 5e c9 [2] 52 c3 [2] 45 c8 [2] 5e 86 [2] 63 }

  condition:
    any of them
}