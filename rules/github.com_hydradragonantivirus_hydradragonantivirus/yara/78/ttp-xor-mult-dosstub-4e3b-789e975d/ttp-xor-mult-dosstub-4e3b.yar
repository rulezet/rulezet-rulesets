rule TTP_XOR_MULT_DOSStub_4e3b {
  strings:
    $key_4e3b = { 1a 53 [2] 6e 4b [2] 29 49 [2] 6e 58 [2] 20 54 [2] 2c 5e [2] 3b 55 [2] 20 1b [2] 1d }

  condition:
    any of them
}