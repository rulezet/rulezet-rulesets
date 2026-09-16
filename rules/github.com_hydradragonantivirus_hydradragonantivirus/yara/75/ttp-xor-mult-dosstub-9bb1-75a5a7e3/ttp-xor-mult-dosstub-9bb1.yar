rule TTP_XOR_MULT_DOSStub_9bb1 {
  strings:
    $key_9bb1 = { cf d9 [2] bb c1 [2] fc c3 [2] bb d2 [2] f5 de [2] f9 d4 [2] ee df [2] f5 91 [2] c8 }

  condition:
    any of them
}