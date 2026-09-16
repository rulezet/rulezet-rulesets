rule TTP_XOR_MULT_DOSStub_44e9 {
  strings:
    $key_44e9 = { 10 81 [2] 64 99 [2] 23 9b [2] 64 8a [2] 2a 86 [2] 26 8c [2] 31 87 [2] 2a c9 [2] 17 }

  condition:
    any of them
}