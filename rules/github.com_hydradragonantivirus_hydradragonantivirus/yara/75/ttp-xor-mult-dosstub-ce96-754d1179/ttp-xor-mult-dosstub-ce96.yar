rule TTP_XOR_MULT_DOSStub_ce96 {
  strings:
    $key_ce96 = { 9a fe [2] ee e6 [2] a9 e4 [2] ee f5 [2] a0 f9 [2] ac f3 [2] bb f8 [2] a0 b6 [2] 9d }

  condition:
    any of them
}