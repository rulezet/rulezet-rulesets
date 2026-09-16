rule TTP_XOR_MULT_DOSStub_25a6 {
  strings:
    $key_25a6 = { 71 ce [2] 05 d6 [2] 42 d4 [2] 05 c5 [2] 4b c9 [2] 47 c3 [2] 50 c8 [2] 4b 86 [2] 76 }

  condition:
    any of them
}