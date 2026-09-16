rule TTP_XOR_MULT_DOSStub_425f {
  strings:
    $key_425f = { 16 37 [2] 62 2f [2] 25 2d [2] 62 3c [2] 2c 30 [2] 20 3a [2] 37 31 [2] 2c 7f [2] 11 }

  condition:
    any of them
}