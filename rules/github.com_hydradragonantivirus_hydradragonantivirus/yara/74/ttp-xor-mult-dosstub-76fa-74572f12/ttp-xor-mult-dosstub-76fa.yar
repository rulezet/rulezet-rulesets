rule TTP_XOR_MULT_DOSStub_76fa {
  strings:
    $key_76fa = { 22 92 [2] 56 8a [2] 11 88 [2] 56 99 [2] 18 95 [2] 14 9f [2] 03 94 [2] 18 da [2] 25 }

  condition:
    any of them
}