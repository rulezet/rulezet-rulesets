rule TTP_XOR_MULT_DOSStub_2c1d {
  strings:
    $key_2c1d = { 78 75 [2] 0c 6d [2] 4b 6f [2] 0c 7e [2] 42 72 [2] 4e 78 [2] 59 73 [2] 42 3d [2] 7f }

  condition:
    any of them
}