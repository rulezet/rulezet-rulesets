rule TTP_XOR_MULT_DOSStub_79ca {
  strings:
    $key_79ca = { 2d a2 [2] 59 ba [2] 1e b8 [2] 59 a9 [2] 17 a5 [2] 1b af [2] 0c a4 [2] 17 ea [2] 2a }

  condition:
    any of them
}