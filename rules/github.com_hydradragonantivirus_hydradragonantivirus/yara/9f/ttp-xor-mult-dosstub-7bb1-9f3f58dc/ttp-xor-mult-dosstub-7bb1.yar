rule TTP_XOR_MULT_DOSStub_7bb1 {
  strings:
    $key_7bb1 = { 2f d9 [2] 5b c1 [2] 1c c3 [2] 5b d2 [2] 15 de [2] 19 d4 [2] 0e df [2] 15 91 [2] 28 }

  condition:
    any of them
}