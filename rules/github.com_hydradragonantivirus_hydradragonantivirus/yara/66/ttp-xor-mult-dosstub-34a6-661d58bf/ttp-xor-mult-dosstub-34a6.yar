rule TTP_XOR_MULT_DOSStub_34a6 {
  strings:
    $key_34a6 = { 60 ce [2] 14 d6 [2] 53 d4 [2] 14 c5 [2] 5a c9 [2] 56 c3 [2] 41 c8 [2] 5a 86 [2] 67 }

  condition:
    any of them
}