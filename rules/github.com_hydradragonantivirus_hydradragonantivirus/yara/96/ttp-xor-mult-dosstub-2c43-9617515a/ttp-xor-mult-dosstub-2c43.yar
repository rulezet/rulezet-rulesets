rule TTP_XOR_MULT_DOSStub_2c43 {
  strings:
    $key_2c43 = { 78 2b [2] 0c 33 [2] 4b 31 [2] 0c 20 [2] 42 2c [2] 4e 26 [2] 59 2d [2] 42 63 [2] 7f }

  condition:
    any of them
}