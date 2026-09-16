rule TTP_XOR_MULT_DOSStub_17a6 {
  strings:
    $key_17a6 = { 43 ce [2] 37 d6 [2] 70 d4 [2] 37 c5 [2] 79 c9 [2] 75 c3 [2] 62 c8 [2] 79 86 [2] 44 }

  condition:
    any of them
}