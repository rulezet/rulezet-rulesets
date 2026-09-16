rule TTP_XOR_MULT_DOSStub_425d {
  strings:
    $key_425d = { 16 35 [2] 62 2d [2] 25 2f [2] 62 3e [2] 2c 32 [2] 20 38 [2] 37 33 [2] 2c 7d [2] 11 }

  condition:
    any of them
}