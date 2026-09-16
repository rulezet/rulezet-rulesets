rule TTP_XOR_MULT_DOSStub_4e2e {
  strings:
    $key_4e2e = { 1a 46 [2] 6e 5e [2] 29 5c [2] 6e 4d [2] 20 41 [2] 2c 4b [2] 3b 40 [2] 20 0e [2] 1d }

  condition:
    any of them
}