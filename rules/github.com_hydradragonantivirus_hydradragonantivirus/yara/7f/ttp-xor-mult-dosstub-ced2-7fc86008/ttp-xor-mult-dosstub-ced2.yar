rule TTP_XOR_MULT_DOSStub_ced2 {
  strings:
    $key_ced2 = { 9a ba [2] ee a2 [2] a9 a0 [2] ee b1 [2] a0 bd [2] ac b7 [2] bb bc [2] a0 f2 [2] 9d }

  condition:
    any of them
}