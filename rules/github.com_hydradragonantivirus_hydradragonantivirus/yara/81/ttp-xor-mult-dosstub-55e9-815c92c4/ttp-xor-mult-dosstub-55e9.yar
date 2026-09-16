rule TTP_XOR_MULT_DOSStub_55e9 {
  strings:
    $key_55e9 = { 01 81 [2] 75 99 [2] 32 9b [2] 75 8a [2] 3b 86 [2] 37 8c [2] 20 87 [2] 3b c9 [2] 06 }

  condition:
    any of them
}