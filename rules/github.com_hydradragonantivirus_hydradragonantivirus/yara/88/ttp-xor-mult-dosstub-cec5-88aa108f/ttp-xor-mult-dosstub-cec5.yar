rule TTP_XOR_MULT_DOSStub_cec5 {
  strings:
    $key_cec5 = { 9a ad [2] ee b5 [2] a9 b7 [2] ee a6 [2] a0 aa [2] ac a0 [2] bb ab [2] a0 e5 [2] 9d }

  condition:
    any of them
}