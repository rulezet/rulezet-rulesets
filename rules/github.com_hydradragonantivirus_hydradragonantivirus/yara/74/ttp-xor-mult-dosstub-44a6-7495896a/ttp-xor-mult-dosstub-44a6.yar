rule TTP_XOR_MULT_DOSStub_44a6 {
  strings:
    $key_44a6 = { 10 ce [2] 64 d6 [2] 23 d4 [2] 64 c5 [2] 2a c9 [2] 26 c3 [2] 31 c8 [2] 2a 86 [2] 17 }

  condition:
    any of them
}