rule TTP_XOR_MULT_DOSStub_9bb3 {
  strings:
    $key_9bb3 = { cf db [2] bb c3 [2] fc c1 [2] bb d0 [2] f5 dc [2] f9 d6 [2] ee dd [2] f5 93 [2] c8 }

  condition:
    any of them
}