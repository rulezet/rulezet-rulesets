rule TTP_XOR_MULT_DOSStub_4e55 {
  strings:
    $key_4e55 = { 1a 3d [2] 6e 25 [2] 29 27 [2] 6e 36 [2] 20 3a [2] 2c 30 [2] 3b 3b [2] 20 75 [2] 1d }

  condition:
    any of them
}