rule TTP_XOR_MULT_DOSStub_63e9 {
  strings:
    $key_63e9 = { 37 81 [2] 43 99 [2] 04 9b [2] 43 8a [2] 0d 86 [2] 01 8c [2] 16 87 [2] 0d c9 [2] 30 }

  condition:
    any of them
}