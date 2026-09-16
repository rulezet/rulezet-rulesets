rule TTP_XOR_MULT_DOSStub_cf92 {
  strings:
    $key_cf92 = { 9b fa [2] ef e2 [2] a8 e0 [2] ef f1 [2] a1 fd [2] ad f7 [2] ba fc [2] a1 b2 [2] 9c }

  condition:
    any of them
}