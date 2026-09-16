rule TTP_XOR_MULT_DOSStub_4e40 {
  strings:
    $key_4e40 = { 1a 28 [2] 6e 30 [2] 29 32 [2] 6e 23 [2] 20 2f [2] 2c 25 [2] 3b 2e [2] 20 60 [2] 1d }

  condition:
    any of them
}