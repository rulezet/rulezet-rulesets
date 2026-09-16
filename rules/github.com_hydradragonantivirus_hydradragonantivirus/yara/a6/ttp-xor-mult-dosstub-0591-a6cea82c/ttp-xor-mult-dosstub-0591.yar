rule TTP_XOR_MULT_DOSStub_0591 {
  strings:
    $key_0591 = { 51 f9 [2] 25 e1 [2] 62 e3 [2] 25 f2 [2] 6b fe [2] 67 f4 [2] 70 ff [2] 6b b1 [2] 56 }

  condition:
    any of them
}