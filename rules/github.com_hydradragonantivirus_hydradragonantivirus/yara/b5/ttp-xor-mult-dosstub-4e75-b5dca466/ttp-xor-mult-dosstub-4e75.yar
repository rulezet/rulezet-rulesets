rule TTP_XOR_MULT_DOSStub_4e75 {
  strings:
    $key_4e75 = { 1a 1d [2] 6e 05 [2] 29 07 [2] 6e 16 [2] 20 1a [2] 2c 10 [2] 3b 1b [2] 20 55 [2] 1d }

  condition:
    any of them
}