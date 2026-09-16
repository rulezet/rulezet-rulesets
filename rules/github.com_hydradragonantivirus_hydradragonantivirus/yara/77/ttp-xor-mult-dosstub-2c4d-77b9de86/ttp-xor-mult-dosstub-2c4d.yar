rule TTP_XOR_MULT_DOSStub_2c4d {
  strings:
    $key_2c4d = { 78 25 [2] 0c 3d [2] 4b 3f [2] 0c 2e [2] 42 22 [2] 4e 28 [2] 59 23 [2] 42 6d [2] 7f }

  condition:
    any of them
}