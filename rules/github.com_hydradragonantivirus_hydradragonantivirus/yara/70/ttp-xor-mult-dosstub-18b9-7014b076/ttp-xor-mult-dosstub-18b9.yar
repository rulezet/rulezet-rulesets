rule TTP_XOR_MULT_DOSStub_18b9 {
  strings:
    $key_18b9 = { 4c d1 [2] 38 c9 [2] 7f cb [2] 38 da [2] 76 d6 [2] 7a dc [2] 6d d7 [2] 76 99 [2] 4b }

  condition:
    any of them
}