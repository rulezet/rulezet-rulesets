rule TTP_XOR_MULT_DOSStub_9ba8 {
  strings:
    $key_9ba8 = { cf c0 [2] bb d8 [2] fc da [2] bb cb [2] f5 c7 [2] f9 cd [2] ee c6 [2] f5 88 [2] c8 }

  condition:
    any of them
}