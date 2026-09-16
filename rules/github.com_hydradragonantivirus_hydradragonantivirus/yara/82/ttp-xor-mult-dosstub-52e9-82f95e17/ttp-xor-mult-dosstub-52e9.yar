rule TTP_XOR_MULT_DOSStub_52e9 {
  strings:
    $key_52e9 = { 06 81 [2] 72 99 [2] 35 9b [2] 72 8a [2] 3c 86 [2] 30 8c [2] 27 87 [2] 3c c9 [2] 01 }

  condition:
    any of them
}