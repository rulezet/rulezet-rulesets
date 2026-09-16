rule TTP_XOR_MULT_DOSStub_5591 {
  strings:
    $key_5591 = { 01 f9 [2] 75 e1 [2] 32 e3 [2] 75 f2 [2] 3b fe [2] 37 f4 [2] 20 ff [2] 3b b1 [2] 06 }

  condition:
    any of them
}