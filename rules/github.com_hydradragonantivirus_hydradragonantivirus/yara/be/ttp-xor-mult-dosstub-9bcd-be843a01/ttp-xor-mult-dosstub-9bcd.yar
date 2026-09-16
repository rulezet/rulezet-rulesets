rule TTP_XOR_MULT_DOSStub_9bcd {
  strings:
    $key_9bcd = { cf a5 [2] bb bd [2] fc bf [2] bb ae [2] f5 a2 [2] f9 a8 [2] ee a3 [2] f5 ed [2] c8 }

  condition:
    any of them
}