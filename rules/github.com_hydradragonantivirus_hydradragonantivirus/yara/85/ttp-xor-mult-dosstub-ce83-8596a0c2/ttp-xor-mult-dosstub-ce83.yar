rule TTP_XOR_MULT_DOSStub_ce83 {
  strings:
    $key_ce83 = { 9a eb [2] ee f3 [2] a9 f1 [2] ee e0 [2] a0 ec [2] ac e6 [2] bb ed [2] a0 a3 [2] 9d }

  condition:
    any of them
}