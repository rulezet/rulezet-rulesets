rule TTP_XOR_MULT_DOSStub_7591 {
  strings:
    $key_7591 = { 21 f9 [2] 55 e1 [2] 12 e3 [2] 55 f2 [2] 1b fe [2] 17 f4 [2] 00 ff [2] 1b b1 [2] 26 }

  condition:
    any of them
}