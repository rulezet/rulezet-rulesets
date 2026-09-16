rule TTP_XOR_MULT_DOSStub_4e7e {
  strings:
    $key_4e7e = { 1a 16 [2] 6e 0e [2] 29 0c [2] 6e 1d [2] 20 11 [2] 2c 1b [2] 3b 10 [2] 20 5e [2] 1d }

  condition:
    any of them
}