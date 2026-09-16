rule TTP_XOR_MULT_DOSStub_70fa {
  strings:
    $key_70fa = { 24 92 [2] 50 8a [2] 17 88 [2] 50 99 [2] 1e 95 [2] 12 9f [2] 05 94 [2] 1e da [2] 23 }

  condition:
    any of them
}