rule TTP_XOR_MULT_DOSStub_49b7 {
  strings:
    $key_49b7 = { 1d df [2] 69 c7 [2] 2e c5 [2] 69 d4 [2] 27 d8 [2] 2b d2 [2] 3c d9 [2] 27 97 [2] 1a }

  condition:
    any of them
}