rule TTP_XOR_MULT_DOSStub_9ba3 {
  strings:
    $key_9ba3 = { cf cb [2] bb d3 [2] fc d1 [2] bb c0 [2] f5 cc [2] f9 c6 [2] ee cd [2] f5 83 [2] c8 }

  condition:
    any of them
}