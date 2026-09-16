rule TTP_XOR_MULT_DOSStub_779a {
  strings:
    $key_779a = { 23 f2 [2] 57 ea [2] 10 e8 [2] 57 f9 [2] 19 f5 [2] 15 ff [2] 02 f4 [2] 19 ba [2] 24 }

  condition:
    any of them
}