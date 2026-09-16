rule TTP_XOR_MULT_DOSStub_1591 {
  strings:
    $key_1591 = { 41 f9 [2] 35 e1 [2] 72 e3 [2] 35 f2 [2] 7b fe [2] 77 f4 [2] 60 ff [2] 7b b1 [2] 46 }

  condition:
    any of them
}