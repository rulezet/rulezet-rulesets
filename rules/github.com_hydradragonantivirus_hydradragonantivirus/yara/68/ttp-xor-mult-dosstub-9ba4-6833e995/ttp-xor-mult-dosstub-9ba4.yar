rule TTP_XOR_MULT_DOSStub_9ba4 {
  strings:
    $key_9ba4 = { cf cc [2] bb d4 [2] fc d6 [2] bb c7 [2] f5 cb [2] f9 c1 [2] ee ca [2] f5 84 [2] c8 }

  condition:
    any of them
}