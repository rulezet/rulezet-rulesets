rule TTP_XOR_MULT_DOSStub_73e7 {
  strings:
    $key_73e7 = { 27 8f [2] 53 97 [2] 14 95 [2] 53 84 [2] 1d 88 [2] 11 82 [2] 06 89 [2] 1d c7 [2] 20 }

  condition:
    any of them
}