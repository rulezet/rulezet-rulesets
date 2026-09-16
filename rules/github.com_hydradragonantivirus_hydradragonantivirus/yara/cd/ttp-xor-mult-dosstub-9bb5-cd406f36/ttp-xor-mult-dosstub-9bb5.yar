rule TTP_XOR_MULT_DOSStub_9bb5 {
  strings:
    $key_9bb5 = { cf dd [2] bb c5 [2] fc c7 [2] bb d6 [2] f5 da [2] f9 d0 [2] ee db [2] f5 95 [2] c8 }

  condition:
    any of them
}