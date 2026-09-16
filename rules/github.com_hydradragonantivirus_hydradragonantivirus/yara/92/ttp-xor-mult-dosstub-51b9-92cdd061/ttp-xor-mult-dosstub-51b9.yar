rule TTP_XOR_MULT_DOSStub_51b9 {
  strings:
    $key_51b9 = { 05 d1 [2] 71 c9 [2] 36 cb [2] 71 da [2] 3f d6 [2] 33 dc [2] 24 d7 [2] 3f 99 [2] 02 }

  condition:
    any of them
}