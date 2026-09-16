rule TTP_XOR_MULT_DOSStub_46e4 {
  strings:
    $key_46e4 = { 12 8c [2] 66 94 [2] 21 96 [2] 66 87 [2] 28 8b [2] 24 81 [2] 33 8a [2] 28 c4 [2] 15 }

  condition:
    any of them
}