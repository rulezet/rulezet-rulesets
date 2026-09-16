rule TTP_XOR_MULT_DOSStub_cecb {
  strings:
    $key_cecb = { 9a a3 [2] ee bb [2] a9 b9 [2] ee a8 [2] a0 a4 [2] ac ae [2] bb a5 [2] a0 eb [2] 9d }

  condition:
    any of them
}