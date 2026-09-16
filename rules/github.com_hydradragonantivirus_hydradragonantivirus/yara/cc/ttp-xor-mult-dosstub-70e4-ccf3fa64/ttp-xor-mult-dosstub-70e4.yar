rule TTP_XOR_MULT_DOSStub_70e4 {
  strings:
    $key_70e4 = { 24 8c [2] 50 94 [2] 17 96 [2] 50 87 [2] 1e 8b [2] 12 81 [2] 05 8a [2] 1e c4 [2] 23 }

  condition:
    any of them
}