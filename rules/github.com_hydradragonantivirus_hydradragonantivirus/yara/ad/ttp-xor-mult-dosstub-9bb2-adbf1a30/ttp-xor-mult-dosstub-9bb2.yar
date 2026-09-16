rule TTP_XOR_MULT_DOSStub_9bb2 {
  strings:
    $key_9bb2 = { cf da [2] bb c2 [2] fc c0 [2] bb d1 [2] f5 dd [2] f9 d7 [2] ee dc [2] f5 92 [2] c8 }

  condition:
    any of them
}