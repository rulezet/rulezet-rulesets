rule TTP_XOR_MULT_DOSStub_4e5d {
  strings:
    $key_4e5d = { 1a 35 [2] 6e 2d [2] 29 2f [2] 6e 3e [2] 20 32 [2] 2c 38 [2] 3b 33 [2] 20 7d [2] 1d }

  condition:
    any of them
}