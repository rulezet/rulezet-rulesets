rule TTP_XOR_MULT_DOSStub_73e2 {
  strings:
    $key_73e2 = { 27 8a [2] 53 92 [2] 14 90 [2] 53 81 [2] 1d 8d [2] 11 87 [2] 06 8c [2] 1d c2 [2] 20 }

  condition:
    any of them
}