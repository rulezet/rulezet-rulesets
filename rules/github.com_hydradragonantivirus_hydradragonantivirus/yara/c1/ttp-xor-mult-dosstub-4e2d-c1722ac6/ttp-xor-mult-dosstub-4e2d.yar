rule TTP_XOR_MULT_DOSStub_4e2d {
  strings:
    $key_4e2d = { 1a 45 [2] 6e 5d [2] 29 5f [2] 6e 4e [2] 20 42 [2] 2c 48 [2] 3b 43 [2] 20 0d [2] 1d }

  condition:
    any of them
}