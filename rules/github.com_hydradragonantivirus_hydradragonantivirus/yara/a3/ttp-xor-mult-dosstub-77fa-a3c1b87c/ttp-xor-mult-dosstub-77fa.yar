rule TTP_XOR_MULT_DOSStub_77fa {
  strings:
    $key_77fa = { 23 92 [2] 57 8a [2] 10 88 [2] 57 99 [2] 19 95 [2] 15 9f [2] 02 94 [2] 19 da [2] 24 }

  condition:
    any of them
}