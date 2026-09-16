rule TTP_XOR_MULT_DOSStub_ce84 {
  strings:
    $key_ce84 = { 9a ec [2] ee f4 [2] a9 f6 [2] ee e7 [2] a0 eb [2] ac e1 [2] bb ea [2] a0 a4 [2] 9d }

  condition:
    any of them
}