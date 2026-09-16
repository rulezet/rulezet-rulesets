rule TTP_XOR_MULT_DOSStub_02ca {
  strings:
    $key_02ca = { 56 a2 [2] 22 ba [2] 65 b8 [2] 22 a9 [2] 6c a5 [2] 60 af [2] 77 a4 [2] 6c ea [2] 51 }

  condition:
    any of them
}