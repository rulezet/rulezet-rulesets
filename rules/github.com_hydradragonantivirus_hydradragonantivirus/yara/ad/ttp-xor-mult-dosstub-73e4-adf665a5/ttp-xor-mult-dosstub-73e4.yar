rule TTP_XOR_MULT_DOSStub_73e4 {
  strings:
    $key_73e4 = { 27 8c [2] 53 94 [2] 14 96 [2] 53 87 [2] 1d 8b [2] 11 81 [2] 06 8a [2] 1d c4 [2] 20 }

  condition:
    any of them
}