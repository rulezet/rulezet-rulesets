rule TTP_XOR_MULT_DOSStub_63e4 {
  strings:
    $key_63e4 = { 37 8c [2] 43 94 [2] 04 96 [2] 43 87 [2] 0d 8b [2] 01 81 [2] 16 8a [2] 0d c4 [2] 30 }

  condition:
    any of them
}