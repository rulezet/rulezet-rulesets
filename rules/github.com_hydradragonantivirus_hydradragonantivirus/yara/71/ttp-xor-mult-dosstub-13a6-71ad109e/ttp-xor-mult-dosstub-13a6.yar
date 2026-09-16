rule TTP_XOR_MULT_DOSStub_13a6 {
  strings:
    $key_13a6 = { 47 ce [2] 33 d6 [2] 74 d4 [2] 33 c5 [2] 7d c9 [2] 71 c3 [2] 66 c8 [2] 7d 86 [2] 40 }

  condition:
    any of them
}