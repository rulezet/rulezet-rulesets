rule TTP_XOR_MULT_DOSStub_89ab {
  strings:
    $key_89ab = { dd c3 [2] a9 db [2] ee d9 [2] a9 c8 [2] e7 c4 [2] eb ce [2] fc c5 [2] e7 8b [2] da }

  condition:
    any of them
}