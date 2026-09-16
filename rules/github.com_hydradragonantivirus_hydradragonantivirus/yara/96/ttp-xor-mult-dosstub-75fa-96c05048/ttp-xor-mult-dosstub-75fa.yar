rule TTP_XOR_MULT_DOSStub_75fa {
  strings:
    $key_75fa = { 21 92 [2] 55 8a [2] 12 88 [2] 55 99 [2] 1b 95 [2] 17 9f [2] 00 94 [2] 1b da [2] 26 }

  condition:
    any of them
}