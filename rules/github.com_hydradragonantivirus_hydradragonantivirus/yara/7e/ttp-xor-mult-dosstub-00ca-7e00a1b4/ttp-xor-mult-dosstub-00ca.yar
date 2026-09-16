rule TTP_XOR_MULT_DOSStub_00ca {
  strings:
    $key_00ca = { 54 a2 [2] 20 ba [2] 67 b8 [2] 20 a9 [2] 6e a5 [2] 62 af [2] 75 a4 [2] 6e ea [2] 53 }

  condition:
    any of them
}