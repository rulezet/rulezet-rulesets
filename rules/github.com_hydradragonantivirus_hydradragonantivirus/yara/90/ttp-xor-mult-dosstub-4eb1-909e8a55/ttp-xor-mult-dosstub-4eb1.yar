rule TTP_XOR_MULT_DOSStub_4eb1 {
  strings:
    $key_4eb1 = { 1a d9 [2] 6e c1 [2] 29 c3 [2] 6e d2 [2] 20 de [2] 2c d4 [2] 3b df [2] 20 91 [2] 1d }

  condition:
    any of them
}