rule TTP_XOR_MULT_DOSStub_a0b9 {
  strings:
    $key_a0b9 = { f4 d1 [2] 80 c9 [2] c7 cb [2] 80 da [2] ce d6 [2] c2 dc [2] d5 d7 [2] ce 99 [2] f3 }

  condition:
    any of them
}