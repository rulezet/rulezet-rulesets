rule TTP_XOR_MULT_DOSStub_60ca {
  strings:
    $key_60ca = { 34 a2 [2] 40 ba [2] 07 b8 [2] 40 a9 [2] 0e a5 [2] 02 af [2] 15 a4 [2] 0e ea [2] 33 }

  condition:
    any of them
}