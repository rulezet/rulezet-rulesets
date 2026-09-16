rule TTP_XOR_MULT_DOSStub_ced4 {
  strings:
    $key_ced4 = { 9a bc [2] ee a4 [2] a9 a6 [2] ee b7 [2] a0 bb [2] ac b1 [2] bb ba [2] a0 f4 [2] 9d }

  condition:
    any of them
}