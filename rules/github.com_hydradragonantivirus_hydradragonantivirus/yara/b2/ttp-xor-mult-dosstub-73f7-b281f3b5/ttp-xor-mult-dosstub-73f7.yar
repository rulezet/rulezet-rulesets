rule TTP_XOR_MULT_DOSStub_73f7 {
  strings:
    $key_73f7 = { 27 9f [2] 53 87 [2] 14 85 [2] 53 94 [2] 1d 98 [2] 11 92 [2] 06 99 [2] 1d d7 [2] 20 }

  condition:
    any of them
}