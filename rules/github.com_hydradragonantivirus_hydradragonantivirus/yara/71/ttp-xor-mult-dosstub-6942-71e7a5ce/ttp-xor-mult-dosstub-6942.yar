rule TTP_XOR_MULT_DOSStub_6942 {
  strings:
    $key_6942 = { 3d 2a [2] 49 32 [2] 0e 30 [2] 49 21 [2] 07 2d [2] 0b 27 [2] 1c 2c [2] 07 62 [2] 3a }

  condition:
    any of them
}