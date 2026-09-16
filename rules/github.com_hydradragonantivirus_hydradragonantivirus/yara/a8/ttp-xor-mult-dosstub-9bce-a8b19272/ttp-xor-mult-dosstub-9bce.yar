rule TTP_XOR_MULT_DOSStub_9bce {
  strings:
    $key_9bce = { cf a6 [2] bb be [2] fc bc [2] bb ad [2] f5 a1 [2] f9 ab [2] ee a0 [2] f5 ee [2] c8 }

  condition:
    any of them
}