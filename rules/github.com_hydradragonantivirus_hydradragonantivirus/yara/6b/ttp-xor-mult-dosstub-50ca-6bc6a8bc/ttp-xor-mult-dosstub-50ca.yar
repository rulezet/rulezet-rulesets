rule TTP_XOR_MULT_DOSStub_50ca {
  strings:
    $key_50ca = { 04 a2 [2] 70 ba [2] 37 b8 [2] 70 a9 [2] 3e a5 [2] 32 af [2] 25 a4 [2] 3e ea [2] 03 }

  condition:
    any of them
}