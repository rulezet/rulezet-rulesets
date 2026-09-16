rule TTP_XOR_MULT_DOSStub_47ca {
  strings:
    $key_47ca = { 13 a2 [2] 67 ba [2] 20 b8 [2] 67 a9 [2] 29 a5 [2] 25 af [2] 32 a4 [2] 29 ea [2] 14 }

  condition:
    any of them
}