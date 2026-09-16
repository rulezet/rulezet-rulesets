rule TTP_XOR_MULT_DOSStub_ce86 {
  strings:
    $key_ce86 = { 9a ee [2] ee f6 [2] a9 f4 [2] ee e5 [2] a0 e9 [2] ac e3 [2] bb e8 [2] a0 a6 [2] 9d }

  condition:
    any of them
}