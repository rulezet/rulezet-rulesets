rule TTP_XOR_MULT_DOSStub_ce90 {
  strings:
    $key_ce90 = { 9a f8 [2] ee e0 [2] a9 e2 [2] ee f3 [2] a0 ff [2] ac f5 [2] bb fe [2] a0 b0 [2] 9d }

  condition:
    any of them
}