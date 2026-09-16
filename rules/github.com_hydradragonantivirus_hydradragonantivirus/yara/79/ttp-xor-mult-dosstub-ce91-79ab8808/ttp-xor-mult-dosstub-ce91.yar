rule TTP_XOR_MULT_DOSStub_ce91 {
  strings:
    $key_ce91 = { 9a f9 [2] ee e1 [2] a9 e3 [2] ee f2 [2] a0 fe [2] ac f4 [2] bb ff [2] a0 b1 [2] 9d }

  condition:
    any of them
}