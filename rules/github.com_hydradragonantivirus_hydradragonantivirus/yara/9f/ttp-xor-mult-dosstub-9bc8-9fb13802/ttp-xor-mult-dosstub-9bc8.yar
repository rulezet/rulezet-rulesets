rule TTP_XOR_MULT_DOSStub_9bc8 {
  strings:
    $key_9bc8 = { cf a0 [2] bb b8 [2] fc ba [2] bb ab [2] f5 a7 [2] f9 ad [2] ee a6 [2] f5 e8 [2] c8 }

  condition:
    any of them
}