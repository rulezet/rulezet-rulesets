rule TTP_XOR_MULT_DOSStub_469a {
  strings:
    $key_469a = { 12 f2 [2] 66 ea [2] 21 e8 [2] 66 f9 [2] 28 f5 [2] 24 ff [2] 33 f4 [2] 28 ba [2] 15 }

  condition:
    any of them
}