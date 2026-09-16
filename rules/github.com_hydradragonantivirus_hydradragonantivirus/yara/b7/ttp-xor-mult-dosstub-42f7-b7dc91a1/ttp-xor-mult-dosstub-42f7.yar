rule TTP_XOR_MULT_DOSStub_42f7 {
  strings:
    $key_42f7 = { 16 9f [2] 62 87 [2] 25 85 [2] 62 94 [2] 2c 98 [2] 20 92 [2] 37 99 [2] 2c d7 [2] 11 }

  condition:
    any of them
}