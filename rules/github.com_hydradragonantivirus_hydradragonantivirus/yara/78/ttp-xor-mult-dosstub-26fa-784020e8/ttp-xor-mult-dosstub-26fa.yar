rule TTP_XOR_MULT_DOSStub_26fa {
  strings:
    $key_26fa = { 72 92 [2] 06 8a [2] 41 88 [2] 06 99 [2] 48 95 [2] 44 9f [2] 53 94 [2] 48 da [2] 75 }

  condition:
    any of them
}