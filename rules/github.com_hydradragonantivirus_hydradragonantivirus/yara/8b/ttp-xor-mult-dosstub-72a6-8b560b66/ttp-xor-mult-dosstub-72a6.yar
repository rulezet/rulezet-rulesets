rule TTP_XOR_MULT_DOSStub_72a6 {
  strings:
    $key_72a6 = { 26 ce [2] 52 d6 [2] 15 d4 [2] 52 c5 [2] 1c c9 [2] 10 c3 [2] 07 c8 [2] 1c 86 [2] 21 }

  condition:
    any of them
}