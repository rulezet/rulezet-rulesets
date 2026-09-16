rule TTP_XOR_MULT_DOSStub_9bc6 {
  strings:
    $key_9bc6 = { cf ae [2] bb b6 [2] fc b4 [2] bb a5 [2] f5 a9 [2] f9 a3 [2] ee a8 [2] f5 e6 [2] c8 }

  condition:
    any of them
}