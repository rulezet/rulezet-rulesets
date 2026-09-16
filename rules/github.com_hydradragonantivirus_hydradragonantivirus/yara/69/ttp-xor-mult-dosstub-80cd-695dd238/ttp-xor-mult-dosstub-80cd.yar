rule TTP_XOR_MULT_DOSStub_80cd {
  strings:
    $key_80cd = { d4 a5 [2] a0 bd [2] e7 bf [2] a0 ae [2] ee a2 [2] e2 a8 [2] f5 a3 [2] ee ed [2] d3 }

  condition:
    any of them
}