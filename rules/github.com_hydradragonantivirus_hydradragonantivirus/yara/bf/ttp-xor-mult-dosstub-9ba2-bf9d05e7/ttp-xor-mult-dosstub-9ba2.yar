rule TTP_XOR_MULT_DOSStub_9ba2 {
  strings:
    $key_9ba2 = { cf ca [2] bb d2 [2] fc d0 [2] bb c1 [2] f5 cd [2] f9 c7 [2] ee cc [2] f5 82 [2] c8 }

  condition:
    any of them
}