rule TTP_XOR_MULT_DOSStub_2c6d {
  strings:
    $key_2c6d = { 78 05 [2] 0c 1d [2] 4b 1f [2] 0c 0e [2] 42 02 [2] 4e 08 [2] 59 03 [2] 42 4d [2] 7f }

  condition:
    any of them
}