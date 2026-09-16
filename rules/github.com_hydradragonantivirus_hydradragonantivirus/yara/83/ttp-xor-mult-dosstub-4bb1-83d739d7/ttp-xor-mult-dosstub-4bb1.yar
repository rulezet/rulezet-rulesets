rule TTP_XOR_MULT_DOSStub_4bb1 {
  strings:
    $key_4bb1 = { 1f d9 [2] 6b c1 [2] 2c c3 [2] 6b d2 [2] 25 de [2] 29 d4 [2] 3e df [2] 25 91 [2] 18 }

  condition:
    any of them
}