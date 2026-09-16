rule TTP_XOR_MULT_DOSStub_42f1 {
  strings:
    $key_42f1 = { 16 99 [2] 62 81 [2] 25 83 [2] 62 92 [2] 2c 9e [2] 20 94 [2] 37 9f [2] 2c d1 [2] 11 }

  condition:
    any of them
}