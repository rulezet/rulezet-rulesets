rule TTP_XOR_MULT_DOSStub_78fa {
  strings:
    $key_78fa = { 2c 92 [2] 58 8a [2] 1f 88 [2] 58 99 [2] 16 95 [2] 1a 9f [2] 0d 94 [2] 16 da [2] 2b }

  condition:
    any of them
}