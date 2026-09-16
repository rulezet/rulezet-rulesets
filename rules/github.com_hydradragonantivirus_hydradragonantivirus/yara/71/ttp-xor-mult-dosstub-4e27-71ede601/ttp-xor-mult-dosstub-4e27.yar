rule TTP_XOR_MULT_DOSStub_4e27 {
  strings:
    $key_4e27 = { 1a 4f [2] 6e 57 [2] 29 55 [2] 6e 44 [2] 20 48 [2] 2c 42 [2] 3b 49 [2] 20 07 [2] 1d }

  condition:
    any of them
}