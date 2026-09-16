rule TTP_XOR_MULT_DOSStub_03b9 {
  strings:
    $key_03b9 = { 57 d1 [2] 23 c9 [2] 64 cb [2] 23 da [2] 6d d6 [2] 61 dc [2] 76 d7 [2] 6d 99 [2] 50 }

  condition:
    any of them
}