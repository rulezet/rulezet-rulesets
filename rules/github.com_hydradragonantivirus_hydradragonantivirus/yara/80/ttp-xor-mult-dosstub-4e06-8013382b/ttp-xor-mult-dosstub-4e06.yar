rule TTP_XOR_MULT_DOSStub_4e06 {
  strings:
    $key_4e06 = { 1a 6e [2] 6e 76 [2] 29 74 [2] 6e 65 [2] 20 69 [2] 2c 63 [2] 3b 68 [2] 20 26 [2] 1d }

  condition:
    any of them
}