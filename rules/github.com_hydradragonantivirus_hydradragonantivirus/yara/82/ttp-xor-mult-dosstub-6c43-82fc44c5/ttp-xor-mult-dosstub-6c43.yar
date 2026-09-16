rule TTP_XOR_MULT_DOSStub_6c43 {
  strings:
    $key_6c43 = { 38 2b [2] 4c 33 [2] 0b 31 [2] 4c 20 [2] 02 2c [2] 0e 26 [2] 19 2d [2] 02 63 [2] 3f }

  condition:
    any of them
}