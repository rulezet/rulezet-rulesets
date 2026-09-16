rule TTP_XOR_MULT_DOSStub_62e9 {
  strings:
    $key_62e9 = { 36 81 [2] 42 99 [2] 05 9b [2] 42 8a [2] 0c 86 [2] 00 8c [2] 17 87 [2] 0c c9 [2] 31 }

  condition:
    any of them
}