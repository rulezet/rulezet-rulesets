rule TTP_XOR_MULT_DOSStub_4e11 {
  strings:
    $key_4e11 = { 1a 79 [2] 6e 61 [2] 29 63 [2] 6e 72 [2] 20 7e [2] 2c 74 [2] 3b 7f [2] 20 31 [2] 1d }

  condition:
    any of them
}