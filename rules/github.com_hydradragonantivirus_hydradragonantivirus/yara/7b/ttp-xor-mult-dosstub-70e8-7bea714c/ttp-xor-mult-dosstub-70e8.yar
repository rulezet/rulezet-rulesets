rule TTP_XOR_MULT_DOSStub_70e8 {
  strings:
    $key_70e8 = { 24 80 [2] 50 98 [2] 17 9a [2] 50 8b [2] 1e 87 [2] 12 8d [2] 05 86 [2] 1e c8 [2] 23 }

  condition:
    any of them
}