rule TTP_XOR_MULT_DOSStub_70e5 {
  strings:
    $key_70e5 = { 24 8d [2] 50 95 [2] 17 97 [2] 50 86 [2] 1e 8a [2] 12 80 [2] 05 8b [2] 1e c5 [2] 23 }

  condition:
    any of them
}