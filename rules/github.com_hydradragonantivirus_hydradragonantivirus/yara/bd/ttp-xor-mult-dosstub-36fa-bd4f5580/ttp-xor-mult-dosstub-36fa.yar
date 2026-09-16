rule TTP_XOR_MULT_DOSStub_36fa {
  strings:
    $key_36fa = { 62 92 [2] 16 8a [2] 51 88 [2] 16 99 [2] 58 95 [2] 54 9f [2] 43 94 [2] 58 da [2] 65 }

  condition:
    any of them
}