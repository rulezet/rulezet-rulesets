rule TTP_XOR_MULT_DOSStub_422a {
  strings:
    $key_422a = { 16 42 [2] 62 5a [2] 25 58 [2] 62 49 [2] 2c 45 [2] 20 4f [2] 37 44 [2] 2c 0a [2] 11 }

  condition:
    any of them
}