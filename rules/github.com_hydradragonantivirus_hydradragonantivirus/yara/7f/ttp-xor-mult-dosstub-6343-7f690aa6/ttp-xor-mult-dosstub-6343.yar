rule TTP_XOR_MULT_DOSStub_6343 {
  strings:
    $key_6343 = { 37 2b [2] 43 33 [2] 04 31 [2] 43 20 [2] 0d 2c [2] 01 26 [2] 16 2d [2] 0d 63 [2] 30 }

  condition:
    any of them
}