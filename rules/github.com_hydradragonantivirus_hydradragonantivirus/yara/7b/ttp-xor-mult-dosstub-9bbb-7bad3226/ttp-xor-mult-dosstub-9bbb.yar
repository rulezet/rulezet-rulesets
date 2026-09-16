rule TTP_XOR_MULT_DOSStub_9bbb {
  strings:
    $key_9bbb = { cf d3 [2] bb cb [2] fc c9 [2] bb d8 [2] f5 d4 [2] f9 de [2] ee d5 [2] f5 9b [2] c8 }

  condition:
    any of them
}