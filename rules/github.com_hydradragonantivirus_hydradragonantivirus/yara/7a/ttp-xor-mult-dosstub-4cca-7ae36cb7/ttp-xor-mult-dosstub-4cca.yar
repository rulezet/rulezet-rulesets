rule TTP_XOR_MULT_DOSStub_4cca {
  strings:
    $key_4cca = { 18 a2 [2] 6c ba [2] 2b b8 [2] 6c a9 [2] 22 a5 [2] 2e af [2] 39 a4 [2] 22 ea [2] 1f }

  condition:
    any of them
}