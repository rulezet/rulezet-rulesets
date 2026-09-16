rule TTP_XOR_MULT_DOSStub_bca6 {
  strings:
    $key_bca6 = { e8 ce [2] 9c d6 [2] db d4 [2] 9c c5 [2] d2 c9 [2] de c3 [2] c9 c8 [2] d2 86 [2] ef }

  condition:
    any of them
}