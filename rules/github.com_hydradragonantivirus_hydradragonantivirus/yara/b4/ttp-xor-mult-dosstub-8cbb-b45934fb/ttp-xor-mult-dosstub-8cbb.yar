rule TTP_XOR_MULT_DOSStub_8cbb {
  strings:
    $key_8cbb = { d8 d3 [2] ac cb [2] eb c9 [2] ac d8 [2] e2 d4 [2] ee de [2] f9 d5 [2] e2 9b [2] df }

  condition:
    any of them
}