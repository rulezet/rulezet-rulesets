rule TTP_XOR_MULT_DOSStub_79b7 {
  strings:
    $key_79b7 = { 2d df [2] 59 c7 [2] 1e c5 [2] 59 d4 [2] 17 d8 [2] 1b d2 [2] 0c d9 [2] 17 97 [2] 2a }

  condition:
    any of them
}