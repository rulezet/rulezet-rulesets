rule TTP_XOR_MULT_DOSStub_cec3 {
  strings:
    $key_cec3 = { 9a ab [2] ee b3 [2] a9 b1 [2] ee a0 [2] a0 ac [2] ac a6 [2] bb ad [2] a0 e3 [2] 9d }

  condition:
    any of them
}