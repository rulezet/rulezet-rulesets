rule TTP_XOR_MULT_DOSStub_ce87 {
  strings:
    $key_ce87 = { 9a ef [2] ee f7 [2] a9 f5 [2] ee e4 [2] a0 e8 [2] ac e2 [2] bb e9 [2] a0 a7 [2] 9d }

  condition:
    any of them
}