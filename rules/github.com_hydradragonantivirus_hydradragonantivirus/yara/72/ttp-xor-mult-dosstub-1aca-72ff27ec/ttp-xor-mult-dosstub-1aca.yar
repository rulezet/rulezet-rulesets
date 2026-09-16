rule TTP_XOR_MULT_DOSStub_1aca {
  strings:
    $key_1aca = { 4e a2 [2] 3a ba [2] 7d b8 [2] 3a a9 [2] 74 a5 [2] 78 af [2] 6f a4 [2] 74 ea [2] 49 }

  condition:
    any of them
}