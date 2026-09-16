rule TTP_XOR_MULT_DOSStub_ced3 {
  strings:
    $key_ced3 = { 9a bb [2] ee a3 [2] a9 a1 [2] ee b0 [2] a0 bc [2] ac b6 [2] bb bd [2] a0 f3 [2] 9d }

  condition:
    any of them
}