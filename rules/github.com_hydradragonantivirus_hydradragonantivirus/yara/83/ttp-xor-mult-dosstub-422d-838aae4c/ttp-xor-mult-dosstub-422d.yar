rule TTP_XOR_MULT_DOSStub_422d {
  strings:
    $key_422d = { 16 45 [2] 62 5d [2] 25 5f [2] 62 4e [2] 2c 42 [2] 20 48 [2] 37 43 [2] 2c 0d [2] 11 }

  condition:
    any of them
}