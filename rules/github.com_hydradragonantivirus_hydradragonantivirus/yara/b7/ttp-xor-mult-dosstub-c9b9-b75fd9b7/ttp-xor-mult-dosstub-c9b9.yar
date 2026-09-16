rule TTP_XOR_MULT_DOSStub_c9b9 {
  strings:
    $key_c9b9 = { 9d d1 [2] e9 c9 [2] ae cb [2] e9 da [2] a7 d6 [2] ab dc [2] bc d7 [2] a7 99 [2] 9a }

  condition:
    any of them
}