rule TTP_XOR_MULT_DOSStub_4e26 {
  strings:
    $key_4e26 = { 1a 4e [2] 6e 56 [2] 29 54 [2] 6e 45 [2] 20 49 [2] 2c 43 [2] 3b 48 [2] 20 06 [2] 1d }

  condition:
    any of them
}