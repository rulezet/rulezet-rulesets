rule TTP_XOR_MULT_DOSStub_a0a0 {
  strings:
    $key_a0a0 = { f4 c8 [2] 80 d0 [2] c7 d2 [2] 80 c3 [2] ce cf [2] c2 c5 [2] d5 ce [2] ce 80 [2] f3 }

  condition:
    any of them
}