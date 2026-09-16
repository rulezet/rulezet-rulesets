rule TTP_XOR_MULT_DOSStub_5491 {
  strings:
    $key_5491 = { 00 f9 [2] 74 e1 [2] 33 e3 [2] 74 f2 [2] 3a fe [2] 36 f4 [2] 21 ff [2] 3a b1 [2] 07 }

  condition:
    any of them
}