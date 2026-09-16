rule TTP_XOR_MULT_DOSStub_62a6 {
  strings:
    $key_62a6 = { 36 ce [2] 42 d6 [2] 05 d4 [2] 42 c5 [2] 0c c9 [2] 00 c3 [2] 17 c8 [2] 0c 86 [2] 31 }

  condition:
    any of them
}