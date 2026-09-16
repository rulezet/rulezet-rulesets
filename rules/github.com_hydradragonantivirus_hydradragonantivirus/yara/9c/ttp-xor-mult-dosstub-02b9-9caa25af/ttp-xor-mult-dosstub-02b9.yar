rule TTP_XOR_MULT_DOSStub_02b9 {
  strings:
    $key_02b9 = { 56 d1 [2] 22 c9 [2] 65 cb [2] 22 da [2] 6c d6 [2] 60 dc [2] 77 d7 [2] 6c 99 [2] 51 }

  condition:
    any of them
}