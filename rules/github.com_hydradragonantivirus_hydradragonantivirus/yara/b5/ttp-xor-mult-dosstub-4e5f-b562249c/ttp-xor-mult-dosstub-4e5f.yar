rule TTP_XOR_MULT_DOSStub_4e5f {
  strings:
    $key_4e5f = { 1a 37 [2] 6e 2f [2] 29 2d [2] 6e 3c [2] 20 30 [2] 2c 3a [2] 3b 31 [2] 20 7f [2] 1d }

  condition:
    any of them
}