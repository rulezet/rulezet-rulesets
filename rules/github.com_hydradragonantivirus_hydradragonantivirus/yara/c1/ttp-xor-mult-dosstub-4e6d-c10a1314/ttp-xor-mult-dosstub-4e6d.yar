rule TTP_XOR_MULT_DOSStub_4e6d {
  strings:
    $key_4e6d = { 1a 05 [2] 6e 1d [2] 29 1f [2] 6e 0e [2] 20 02 [2] 2c 08 [2] 3b 03 [2] 20 4d [2] 1d }

  condition:
    any of them
}