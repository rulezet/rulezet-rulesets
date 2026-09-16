rule TTP_XOR_MULT_DOSStub_07fa {
  strings:
    $key_07fa = { 53 92 [2] 27 8a [2] 60 88 [2] 27 99 [2] 69 95 [2] 65 9f [2] 72 94 [2] 69 da [2] 54 }

  condition:
    any of them
}