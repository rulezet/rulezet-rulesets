rule TTP_XOR_MULT_DOSStub_409a {
  strings:
    $key_409a = { 14 f2 [2] 60 ea [2] 27 e8 [2] 60 f9 [2] 2e f5 [2] 22 ff [2] 35 f4 [2] 2e ba [2] 13 }

  condition:
    any of them
}