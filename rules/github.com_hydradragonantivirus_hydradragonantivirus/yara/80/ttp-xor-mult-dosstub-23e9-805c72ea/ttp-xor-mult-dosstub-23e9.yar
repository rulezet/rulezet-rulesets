rule TTP_XOR_MULT_DOSStub_23e9 {
  strings:
    $key_23e9 = { 77 81 [2] 03 99 [2] 44 9b [2] 03 8a [2] 4d 86 [2] 41 8c [2] 56 87 [2] 4d c9 [2] 70 }

  condition:
    any of them
}