rule TTP_XOR_MULT_DOSStub_72b9 {
  strings:
    $key_72b9 = { 26 d1 [2] 52 c9 [2] 15 cb [2] 52 da [2] 1c d6 [2] 10 dc [2] 07 d7 [2] 1c 99 [2] 21 }

  condition:
    any of them
}