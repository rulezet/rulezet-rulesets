rule TTP_XOR_MULT_DOSStub_6da6 {
  strings:
    $key_6da6 = { 39 ce [2] 4d d6 [2] 0a d4 [2] 4d c5 [2] 03 c9 [2] 0f c3 [2] 18 c8 [2] 03 86 [2] 3e }

  condition:
    any of them
}