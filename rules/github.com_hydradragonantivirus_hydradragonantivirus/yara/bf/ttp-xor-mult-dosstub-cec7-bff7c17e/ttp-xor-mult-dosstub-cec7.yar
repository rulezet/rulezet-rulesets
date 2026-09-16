rule TTP_XOR_MULT_DOSStub_cec7 {
  strings:
    $key_cec7 = { 9a af [2] ee b7 [2] a9 b5 [2] ee a4 [2] a0 a8 [2] ac a2 [2] bb a9 [2] a0 e7 [2] 9d }

  condition:
    any of them
}