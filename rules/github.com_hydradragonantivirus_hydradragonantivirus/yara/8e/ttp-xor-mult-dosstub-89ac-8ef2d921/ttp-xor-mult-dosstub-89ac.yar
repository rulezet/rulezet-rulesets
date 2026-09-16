rule TTP_XOR_MULT_DOSStub_89ac {
  strings:
    $key_89ac = { dd c4 [2] a9 dc [2] ee de [2] a9 cf [2] e7 c3 [2] eb c9 [2] fc c2 [2] e7 8c [2] da }

  condition:
    any of them
}