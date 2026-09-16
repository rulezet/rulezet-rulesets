rule TTP_XOR_MULT_DOSStub_3da6 {
  strings:
    $key_3da6 = { 69 ce [2] 1d d6 [2] 5a d4 [2] 1d c5 [2] 53 c9 [2] 5f c3 [2] 48 c8 [2] 53 86 [2] 6e }

  condition:
    any of them
}