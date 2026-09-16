rule TTP_XOR_MULT_DOSStub_21b9 {
  strings:
    $key_21b9 = { 75 d1 [2] 01 c9 [2] 46 cb [2] 01 da [2] 4f d6 [2] 43 dc [2] 54 d7 [2] 4f 99 [2] 72 }

  condition:
    any of them
}