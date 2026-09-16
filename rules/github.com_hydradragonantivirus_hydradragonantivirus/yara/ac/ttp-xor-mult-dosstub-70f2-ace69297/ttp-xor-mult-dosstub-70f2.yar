rule TTP_XOR_MULT_DOSStub_70f2 {
  strings:
    $key_70f2 = { 24 9a [2] 50 82 [2] 17 80 [2] 50 91 [2] 1e 9d [2] 12 97 [2] 05 9c [2] 1e d2 [2] 23 }

  condition:
    any of them
}