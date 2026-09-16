rule TTP_XOR_MULT_DOSStub_4e4e {
  strings:
    $key_4e4e = { 1a 26 [2] 6e 3e [2] 29 3c [2] 6e 2d [2] 20 21 [2] 2c 2b [2] 3b 20 [2] 20 6e [2] 1d }

  condition:
    any of them
}