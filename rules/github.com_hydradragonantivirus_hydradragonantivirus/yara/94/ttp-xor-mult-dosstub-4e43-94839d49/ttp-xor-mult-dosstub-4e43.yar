rule TTP_XOR_MULT_DOSStub_4e43 {
  strings:
    $key_4e43 = { 1a 2b [2] 6e 33 [2] 29 31 [2] 6e 20 [2] 20 2c [2] 2c 26 [2] 3b 2d [2] 20 63 [2] 1d }

  condition:
    any of them
}