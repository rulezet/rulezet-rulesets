rule TTP_XOR_MULT_DOSStub_6442 {
  strings:
    $key_6442 = { 30 2a [2] 44 32 [2] 03 30 [2] 44 21 [2] 0a 2d [2] 06 27 [2] 11 2c [2] 0a 62 [2] 37 }

  condition:
    any of them
}