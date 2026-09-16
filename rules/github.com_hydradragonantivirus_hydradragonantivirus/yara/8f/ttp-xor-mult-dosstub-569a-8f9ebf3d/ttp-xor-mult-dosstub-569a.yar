rule TTP_XOR_MULT_DOSStub_569a {
  strings:
    $key_569a = { 02 f2 [2] 76 ea [2] 31 e8 [2] 76 f9 [2] 38 f5 [2] 34 ff [2] 23 f4 [2] 38 ba [2] 05 }

  condition:
    any of them
}