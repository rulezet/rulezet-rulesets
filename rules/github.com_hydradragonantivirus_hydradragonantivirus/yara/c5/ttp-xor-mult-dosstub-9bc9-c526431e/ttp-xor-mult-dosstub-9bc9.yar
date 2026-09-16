rule TTP_XOR_MULT_DOSStub_9bc9 {
  strings:
    $key_9bc9 = { cf a1 [2] bb b9 [2] fc bb [2] bb aa [2] f5 a6 [2] f9 ac [2] ee a7 [2] f5 e9 [2] c8 }

  condition:
    any of them
}