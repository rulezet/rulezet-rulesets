rule TTP_XOR_MULT_DOSStub_46e9 {
  strings:
    $key_46e9 = { 12 81 [2] 66 99 [2] 21 9b [2] 66 8a [2] 28 86 [2] 24 8c [2] 33 87 [2] 28 c9 [2] 15 }

  condition:
    any of them
}