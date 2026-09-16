rule TTP_XOR_MULT_DOSStub_89a1 {
  strings:
    $key_89a1 = { dd c9 [2] a9 d1 [2] ee d3 [2] a9 c2 [2] e7 ce [2] eb c4 [2] fc cf [2] e7 81 [2] da }

  condition:
    any of them
}