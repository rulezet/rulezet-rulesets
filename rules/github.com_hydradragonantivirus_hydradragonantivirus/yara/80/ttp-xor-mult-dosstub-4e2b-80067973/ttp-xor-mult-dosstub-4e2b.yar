rule TTP_XOR_MULT_DOSStub_4e2b {
  strings:
    $key_4e2b = { 1a 43 [2] 6e 5b [2] 29 59 [2] 6e 48 [2] 20 44 [2] 2c 4e [2] 3b 45 [2] 20 0b [2] 1d }

  condition:
    any of them
}