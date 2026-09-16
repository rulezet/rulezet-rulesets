rule TTP_XOR_MULT_DOSStub_12a6 {
  strings:
    $key_12a6 = { 46 ce [2] 32 d6 [2] 75 d4 [2] 32 c5 [2] 7c c9 [2] 70 c3 [2] 67 c8 [2] 7c 86 [2] 41 }

  condition:
    any of them
}