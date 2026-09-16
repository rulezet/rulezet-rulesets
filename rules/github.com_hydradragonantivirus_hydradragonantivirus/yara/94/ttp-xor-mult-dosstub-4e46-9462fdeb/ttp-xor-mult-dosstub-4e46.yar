rule TTP_XOR_MULT_DOSStub_4e46 {
  strings:
    $key_4e46 = { 1a 2e [2] 6e 36 [2] 29 34 [2] 6e 25 [2] 20 29 [2] 2c 23 [2] 3b 28 [2] 20 66 [2] 1d }

  condition:
    any of them
}