rule TTP_XOR_MULT_DOSStub_ced6 {
  strings:
    $key_ced6 = { 9a be [2] ee a6 [2] a9 a4 [2] ee b5 [2] a0 b9 [2] ac b3 [2] bb b8 [2] a0 f6 [2] 9d }

  condition:
    any of them
}