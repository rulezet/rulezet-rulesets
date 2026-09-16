rule TTP_XOR_MULT_DOSStub_ce89 {
  strings:
    $key_ce89 = { 9a e1 [2] ee f9 [2] a9 fb [2] ee ea [2] a0 e6 [2] ac ec [2] bb e7 [2] a0 a9 [2] 9d }

  condition:
    any of them
}