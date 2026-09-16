rule TTP_XOR_MULT_DOSStub_64e9 {
  strings:
    $key_64e9 = { 30 81 [2] 44 99 [2] 03 9b [2] 44 8a [2] 0a 86 [2] 06 8c [2] 11 87 [2] 0a c9 [2] 37 }

  condition:
    any of them
}