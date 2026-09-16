rule TTP_XOR_MULT_DOSStub_6742 {
  strings:
    $key_6742 = { 33 2a [2] 47 32 [2] 00 30 [2] 47 21 [2] 09 2d [2] 05 27 [2] 12 2c [2] 09 62 [2] 34 }

  condition:
    any of them
}