rule TTP_XOR_MULT_DOSStub_7742 {
  strings:
    $key_7742 = { 23 2a [2] 57 32 [2] 10 30 [2] 57 21 [2] 19 2d [2] 15 27 [2] 02 2c [2] 19 62 [2] 24 }

  condition:
    any of them
}