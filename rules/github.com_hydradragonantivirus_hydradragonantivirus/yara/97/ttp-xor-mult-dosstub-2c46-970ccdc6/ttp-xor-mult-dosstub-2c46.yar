rule TTP_XOR_MULT_DOSStub_2c46 {
  strings:
    $key_2c46 = { 78 2e [2] 0c 36 [2] 4b 34 [2] 0c 25 [2] 42 29 [2] 4e 23 [2] 59 28 [2] 42 66 [2] 7f }

  condition:
    any of them
}