rule TTP_XOR_MULT_DOSStub_f4ca {
  strings:
    $key_f4ca = { a0 a2 [2] d4 ba [2] 93 b8 [2] d4 a9 [2] 9a a5 [2] 96 af [2] 81 a4 [2] 9a ea [2] a7 }

  condition:
    any of them
}