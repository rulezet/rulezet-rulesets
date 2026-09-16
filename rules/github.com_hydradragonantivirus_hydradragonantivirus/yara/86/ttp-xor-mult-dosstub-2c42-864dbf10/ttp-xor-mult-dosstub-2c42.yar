rule TTP_XOR_MULT_DOSStub_2c42 {
  strings:
    $key_2c42 = { 78 2a [2] 0c 32 [2] 4b 30 [2] 0c 21 [2] 42 2d [2] 4e 27 [2] 59 2c [2] 42 62 [2] 7f }

  condition:
    any of them
}