rule TTP_XOR_MULT_DOSStub_12ca {
  strings:
    $key_12ca = { 46 a2 [2] 32 ba [2] 75 b8 [2] 32 a9 [2] 7c a5 [2] 70 af [2] 67 a4 [2] 7c ea [2] 41 }

  condition:
    any of them
}