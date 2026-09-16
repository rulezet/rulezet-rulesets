rule TTP_XOR_MULT_DOSStub_70e9 {
  strings:
    $key_70e9 = { 24 81 [2] 50 99 [2] 17 9b [2] 50 8a [2] 1e 86 [2] 12 8c [2] 05 87 [2] 1e c9 [2] 23 }

  condition:
    any of them
}