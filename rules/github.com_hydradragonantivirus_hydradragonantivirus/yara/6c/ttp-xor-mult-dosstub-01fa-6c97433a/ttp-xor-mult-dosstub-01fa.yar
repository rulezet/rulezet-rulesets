rule TTP_XOR_MULT_DOSStub_01fa {
  strings:
    $key_01fa = { 55 92 [2] 21 8a [2] 66 88 [2] 21 99 [2] 6f 95 [2] 63 9f [2] 74 94 [2] 6f da [2] 52 }

  condition:
    any of them
}