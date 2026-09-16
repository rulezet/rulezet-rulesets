rule TTP_XOR_MULT_DOSStub_427d {
  strings:
    $key_427d = { 16 15 [2] 62 0d [2] 25 0f [2] 62 1e [2] 2c 12 [2] 20 18 [2] 37 13 [2] 2c 5d [2] 11 }

  condition:
    any of them
}