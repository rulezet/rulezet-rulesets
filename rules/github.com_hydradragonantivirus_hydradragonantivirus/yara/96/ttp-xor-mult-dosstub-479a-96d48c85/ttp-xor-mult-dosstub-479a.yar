rule TTP_XOR_MULT_DOSStub_479a {
  strings:
    $key_479a = { 13 f2 [2] 67 ea [2] 20 e8 [2] 67 f9 [2] 29 f5 [2] 25 ff [2] 32 f4 [2] 29 ba [2] 14 }

  condition:
    any of them
}