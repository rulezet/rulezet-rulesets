rule TTP_XOR_MULT_DOSStub_4aca {
  strings:
    $key_4aca = { 1e a2 [2] 6a ba [2] 2d b8 [2] 6a a9 [2] 24 a5 [2] 28 af [2] 3f a4 [2] 24 ea [2] 19 }

  condition:
    any of them
}