rule TTP_XOR_MULT_DOSStub_73f1 {
  strings:
    $key_73f1 = { 27 99 [2] 53 81 [2] 14 83 [2] 53 92 [2] 1d 9e [2] 11 94 [2] 06 9f [2] 1d d1 [2] 20 }

  condition:
    any of them
}