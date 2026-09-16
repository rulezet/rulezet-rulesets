rule TTP_XOR_MULT_DOSStub_73b9 {
  strings:
    $key_73b9 = { 27 d1 [2] 53 c9 [2] 14 cb [2] 53 da [2] 1d d6 [2] 11 dc [2] 06 d7 [2] 1d 99 [2] 20 }

  condition:
    any of them
}