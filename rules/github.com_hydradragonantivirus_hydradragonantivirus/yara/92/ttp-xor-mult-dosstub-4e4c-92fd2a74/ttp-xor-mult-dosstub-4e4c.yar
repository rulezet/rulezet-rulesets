rule TTP_XOR_MULT_DOSStub_4e4c {
  strings:
    $key_4e4c = { 1a 24 [2] 6e 3c [2] 29 3e [2] 6e 2f [2] 20 23 [2] 2c 29 [2] 3b 22 [2] 20 6c [2] 1d }

  condition:
    any of them
}