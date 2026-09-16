rule TTP_XOR_MULT_DOSStub_1491 {
  strings:
    $key_1491 = { 40 f9 [2] 34 e1 [2] 73 e3 [2] 34 f2 [2] 7a fe [2] 76 f4 [2] 61 ff [2] 7a b1 [2] 47 }

  condition:
    any of them
}