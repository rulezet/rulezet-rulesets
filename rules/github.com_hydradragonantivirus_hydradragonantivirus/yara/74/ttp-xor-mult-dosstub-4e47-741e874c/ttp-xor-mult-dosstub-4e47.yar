rule TTP_XOR_MULT_DOSStub_4e47 {
  strings:
    $key_4e47 = { 1a 2f [2] 6e 37 [2] 29 35 [2] 6e 24 [2] 20 28 [2] 2c 22 [2] 3b 29 [2] 20 67 [2] 1d }

  condition:
    any of them
}