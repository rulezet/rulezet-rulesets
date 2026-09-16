rule TTP_XOR_MULT_DOSStub_7cca {
  strings:
    $key_7cca = { 28 a2 [2] 5c ba [2] 1b b8 [2] 5c a9 [2] 12 a5 [2] 1e af [2] 09 a4 [2] 12 ea [2] 2f }

  condition:
    any of them
}