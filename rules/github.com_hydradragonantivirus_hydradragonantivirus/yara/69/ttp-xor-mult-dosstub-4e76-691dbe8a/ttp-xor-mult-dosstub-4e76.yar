rule TTP_XOR_MULT_DOSStub_4e76 {
  strings:
    $key_4e76 = { 1a 1e [2] 6e 06 [2] 29 04 [2] 6e 15 [2] 20 19 [2] 2c 13 [2] 3b 18 [2] 20 56 [2] 1d }

  condition:
    any of them
}