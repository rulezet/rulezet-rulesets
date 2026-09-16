rule TTP_XOR_MULT_DOSStub_2c49 {
  strings:
    $key_2c49 = { 78 21 [2] 0c 39 [2] 4b 3b [2] 0c 2a [2] 42 26 [2] 4e 2c [2] 59 27 [2] 42 69 [2] 7f }

  condition:
    any of them
}