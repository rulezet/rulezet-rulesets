rule TTP_XOR_MULT_DOSStub_77ca {
  strings:
    $key_77ca = { 23 a2 [2] 57 ba [2] 10 b8 [2] 57 a9 [2] 19 a5 [2] 15 af [2] 02 a4 [2] 19 ea [2] 24 }

  condition:
    any of them
}