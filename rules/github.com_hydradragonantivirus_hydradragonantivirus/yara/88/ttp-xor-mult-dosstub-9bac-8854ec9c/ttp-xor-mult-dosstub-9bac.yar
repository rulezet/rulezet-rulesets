rule TTP_XOR_MULT_DOSStub_9bac {
  strings:
    $key_9bac = { cf c4 [2] bb dc [2] fc de [2] bb cf [2] f5 c3 [2] f9 c9 [2] ee c2 [2] f5 8c [2] c8 }

  condition:
    any of them
}