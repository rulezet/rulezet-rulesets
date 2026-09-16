rule TTP_XOR_MULT_DOSStub_89bd {
  strings:
    $key_89bd = { dd d5 [2] a9 cd [2] ee cf [2] a9 de [2] e7 d2 [2] eb d8 [2] fc d3 [2] e7 9d [2] da }

  condition:
    any of them
}