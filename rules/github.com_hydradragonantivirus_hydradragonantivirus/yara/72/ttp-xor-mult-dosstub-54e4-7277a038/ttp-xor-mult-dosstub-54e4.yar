rule TTP_XOR_MULT_DOSStub_54e4 {
  strings:
    $key_54e4 = { 00 8c [2] 74 94 [2] 33 96 [2] 74 87 [2] 3a 8b [2] 36 81 [2] 21 8a [2] 3a c4 [2] 07 }

  condition:
    any of them
}