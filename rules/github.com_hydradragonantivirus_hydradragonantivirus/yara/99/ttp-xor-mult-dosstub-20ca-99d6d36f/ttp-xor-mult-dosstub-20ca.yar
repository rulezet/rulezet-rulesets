rule TTP_XOR_MULT_DOSStub_20ca {
  strings:
    $key_20ca = { 74 a2 [2] 00 ba [2] 47 b8 [2] 00 a9 [2] 4e a5 [2] 42 af [2] 55 a4 [2] 4e ea [2] 73 }

  condition:
    any of them
}