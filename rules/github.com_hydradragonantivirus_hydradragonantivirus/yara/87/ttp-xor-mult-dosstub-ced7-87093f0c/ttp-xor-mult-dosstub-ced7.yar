rule TTP_XOR_MULT_DOSStub_ced7 {
  strings:
    $key_ced7 = { 9a bf [2] ee a7 [2] a9 a5 [2] ee b4 [2] a0 b8 [2] ac b2 [2] bb b9 [2] a0 f7 [2] 9d }

  condition:
    any of them
}