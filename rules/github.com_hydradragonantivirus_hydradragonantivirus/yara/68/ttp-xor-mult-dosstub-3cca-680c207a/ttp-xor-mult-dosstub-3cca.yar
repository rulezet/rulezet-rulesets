rule TTP_XOR_MULT_DOSStub_3cca {
  strings:
    $key_3cca = { 68 a2 [2] 1c ba [2] 5b b8 [2] 1c a9 [2] 52 a5 [2] 5e af [2] 49 a4 [2] 52 ea [2] 6f }

  condition:
    any of them
}