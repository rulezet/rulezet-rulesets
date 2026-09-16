rule TTP_XOR_MULT_DOSStub_4252 {
  strings:
    $key_4252 = { 16 3a [2] 62 22 [2] 25 20 [2] 62 31 [2] 2c 3d [2] 20 37 [2] 37 3c [2] 2c 72 [2] 11 }

  condition:
    any of them
}