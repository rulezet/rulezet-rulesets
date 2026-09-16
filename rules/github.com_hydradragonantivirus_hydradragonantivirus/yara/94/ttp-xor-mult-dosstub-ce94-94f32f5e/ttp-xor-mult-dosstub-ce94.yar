rule TTP_XOR_MULT_DOSStub_ce94 {
  strings:
    $key_ce94 = { 9a fc [2] ee e4 [2] a9 e6 [2] ee f7 [2] a0 fb [2] ac f1 [2] bb fa [2] a0 b4 [2] 9d }

  condition:
    any of them
}