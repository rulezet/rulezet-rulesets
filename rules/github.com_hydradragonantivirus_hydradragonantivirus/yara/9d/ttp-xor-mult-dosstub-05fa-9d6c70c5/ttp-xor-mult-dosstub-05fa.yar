rule TTP_XOR_MULT_DOSStub_05fa {
  strings:
    $key_05fa = { 51 92 [2] 25 8a [2] 62 88 [2] 25 99 [2] 6b 95 [2] 67 9f [2] 70 94 [2] 6b da [2] 56 }

  condition:
    any of them
}