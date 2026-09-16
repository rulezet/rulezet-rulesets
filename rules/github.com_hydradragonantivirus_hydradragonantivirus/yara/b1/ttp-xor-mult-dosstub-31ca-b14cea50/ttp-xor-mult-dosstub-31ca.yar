rule TTP_XOR_MULT_DOSStub_31ca {
  strings:
    $key_31ca = { 65 a2 [2] 11 ba [2] 56 b8 [2] 11 a9 [2] 5f a5 [2] 53 af [2] 44 a4 [2] 5f ea [2] 62 }

  condition:
    any of them
}