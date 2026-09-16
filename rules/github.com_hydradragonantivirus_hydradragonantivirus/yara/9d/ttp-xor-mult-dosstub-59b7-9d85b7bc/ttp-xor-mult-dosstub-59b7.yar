rule TTP_XOR_MULT_DOSStub_59b7 {
  strings:
    $key_59b7 = { 0d df [2] 79 c7 [2] 3e c5 [2] 79 d4 [2] 37 d8 [2] 3b d2 [2] 2c d9 [2] 37 97 [2] 0a }

  condition:
    any of them
}