rule TTP_XOR_MULT_DOSStub_4e7b {
  strings:
    $key_4e7b = { 1a 13 [2] 6e 0b [2] 29 09 [2] 6e 18 [2] 20 14 [2] 2c 1e [2] 3b 15 [2] 20 5b [2] 1d }

  condition:
    any of them
}