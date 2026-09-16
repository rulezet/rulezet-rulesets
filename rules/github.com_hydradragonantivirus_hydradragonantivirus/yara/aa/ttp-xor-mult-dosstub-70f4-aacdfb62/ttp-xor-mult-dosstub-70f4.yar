rule TTP_XOR_MULT_DOSStub_70f4 {
  strings:
    $key_70f4 = { 24 9c [2] 50 84 [2] 17 86 [2] 50 97 [2] 1e 9b [2] 12 91 [2] 05 9a [2] 1e d4 [2] 23 }

  condition:
    any of them
}