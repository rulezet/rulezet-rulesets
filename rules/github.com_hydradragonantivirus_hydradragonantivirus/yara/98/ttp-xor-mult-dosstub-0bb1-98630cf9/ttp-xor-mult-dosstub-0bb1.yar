rule TTP_XOR_MULT_DOSStub_0bb1 {
  strings:
    $key_0bb1 = { 5f d9 [2] 2b c1 [2] 6c c3 [2] 2b d2 [2] 65 de [2] 69 d4 [2] 7e df [2] 65 91 [2] 58 }

  condition:
    any of them
}