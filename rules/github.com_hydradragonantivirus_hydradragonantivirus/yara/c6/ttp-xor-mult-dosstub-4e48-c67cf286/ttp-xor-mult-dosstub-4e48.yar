rule TTP_XOR_MULT_DOSStub_4e48 {
  strings:
    $key_4e48 = { 1a 20 [2] 6e 38 [2] 29 3a [2] 6e 2b [2] 20 27 [2] 2c 2d [2] 3b 26 [2] 20 68 [2] 1d }

  condition:
    any of them
}