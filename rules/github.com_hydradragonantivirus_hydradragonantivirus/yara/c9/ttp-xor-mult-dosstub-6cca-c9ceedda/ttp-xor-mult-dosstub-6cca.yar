rule TTP_XOR_MULT_DOSStub_6cca {
  strings:
    $key_6cca = { 38 a2 [2] 4c ba [2] 0b b8 [2] 4c a9 [2] 02 a5 [2] 0e af [2] 19 a4 [2] 02 ea [2] 3f }

  condition:
    any of them
}