rule TTP_XOR_MULT_DOSStub_cec6 {
  strings:
    $key_cec6 = { 9a ae [2] ee b6 [2] a9 b4 [2] ee a5 [2] a0 a9 [2] ac a3 [2] bb a8 [2] a0 e6 [2] 9d }

  condition:
    any of them
}