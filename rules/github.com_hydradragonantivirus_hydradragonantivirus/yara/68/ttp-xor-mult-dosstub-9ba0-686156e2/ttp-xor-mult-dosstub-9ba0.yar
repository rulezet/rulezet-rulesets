rule TTP_XOR_MULT_DOSStub_9ba0 {
  strings:
    $key_9ba0 = { cf c8 [2] bb d0 [2] fc d2 [2] bb c3 [2] f5 cf [2] f9 c5 [2] ee ce [2] f5 80 [2] c8 }

  condition:
    any of them
}