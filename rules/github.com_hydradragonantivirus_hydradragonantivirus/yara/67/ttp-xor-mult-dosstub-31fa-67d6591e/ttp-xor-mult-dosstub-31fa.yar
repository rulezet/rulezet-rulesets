rule TTP_XOR_MULT_DOSStub_31fa {
  strings:
    $key_31fa = { 65 92 [2] 11 8a [2] 56 88 [2] 11 99 [2] 5f 95 [2] 53 9f [2] 44 94 [2] 5f da [2] 62 }

  condition:
    any of them
}