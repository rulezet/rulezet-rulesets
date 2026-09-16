rule TTP_XOR_MULT_DOSStub_4591 {
  strings:
    $key_4591 = { 11 f9 [2] 65 e1 [2] 22 e3 [2] 65 f2 [2] 2b fe [2] 27 f4 [2] 30 ff [2] 2b b1 [2] 16 }

  condition:
    any of them
}