rule TTP_XOR_MULT_DOSStub_424d {
  strings:
    $key_424d = { 16 25 [2] 62 3d [2] 25 3f [2] 62 2e [2] 2c 22 [2] 20 28 [2] 37 23 [2] 2c 6d [2] 11 }

  condition:
    any of them
}