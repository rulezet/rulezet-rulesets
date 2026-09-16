rule TTP_XOR_MULT_DOSStub_4e52 {
  strings:
    $key_4e52 = { 1a 3a [2] 6e 22 [2] 29 20 [2] 6e 31 [2] 20 3d [2] 2c 37 [2] 3b 3c [2] 20 72 [2] 1d }

  condition:
    any of them
}