rule TTP_XOR_MULT_DOSStub_2c5f {
  strings:
    $key_2c5f = { 78 37 [2] 0c 2f [2] 4b 2d [2] 0c 3c [2] 42 30 [2] 4e 3a [2] 59 31 [2] 42 7f [2] 7f }

  condition:
    any of them
}