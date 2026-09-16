rule TTP_XOR_MULT_DOSStub_4e45 {
  strings:
    $key_4e45 = { 1a 2d [2] 6e 35 [2] 29 37 [2] 6e 26 [2] 20 2a [2] 2c 20 [2] 3b 2b [2] 20 65 [2] 1d }

  condition:
    any of them
}