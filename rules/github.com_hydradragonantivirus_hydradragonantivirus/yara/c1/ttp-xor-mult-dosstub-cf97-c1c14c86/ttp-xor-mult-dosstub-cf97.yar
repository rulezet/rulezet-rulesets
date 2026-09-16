rule TTP_XOR_MULT_DOSStub_cf97 {
  strings:
    $key_cf97 = { 9b ff [2] ef e7 [2] a8 e5 [2] ef f4 [2] a1 f8 [2] ad f2 [2] ba f9 [2] a1 b7 [2] 9c }

  condition:
    any of them
}