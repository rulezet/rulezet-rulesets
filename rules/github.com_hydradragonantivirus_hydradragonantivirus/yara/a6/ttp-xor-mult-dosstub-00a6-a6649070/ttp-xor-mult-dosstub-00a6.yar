rule TTP_XOR_MULT_DOSStub_00a6 {
  strings:
    $key_00a6 = { 54 ce [2] 20 d6 [2] 67 d4 [2] 20 c5 [2] 6e c9 [2] 62 c3 [2] 75 c8 [2] 6e 86 [2] 53 }

  condition:
    any of them
}