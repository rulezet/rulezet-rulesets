rule TTP_XOR_MULT_DOSStub_73e0 {
  strings:
    $key_73e0 = { 27 88 [2] 53 90 [2] 14 92 [2] 53 83 [2] 1d 8f [2] 11 85 [2] 06 8e [2] 1d c0 [2] 20 }

  condition:
    any of them
}