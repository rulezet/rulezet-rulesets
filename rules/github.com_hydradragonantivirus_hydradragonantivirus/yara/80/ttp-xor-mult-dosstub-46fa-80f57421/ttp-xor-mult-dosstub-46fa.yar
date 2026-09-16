rule TTP_XOR_MULT_DOSStub_46fa {
  strings:
    $key_46fa = { 12 92 [2] 66 8a [2] 21 88 [2] 66 99 [2] 28 95 [2] 24 9f [2] 33 94 [2] 28 da [2] 15 }

  condition:
    any of them
}