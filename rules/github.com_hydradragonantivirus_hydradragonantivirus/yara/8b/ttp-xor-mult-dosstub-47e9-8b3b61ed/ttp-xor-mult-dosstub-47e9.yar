rule TTP_XOR_MULT_DOSStub_47e9 {
  strings:
    $key_47e9 = { 13 81 [2] 67 99 [2] 20 9b [2] 67 8a [2] 29 86 [2] 25 8c [2] 32 87 [2] 29 c9 [2] 14 }

  condition:
    any of them
}