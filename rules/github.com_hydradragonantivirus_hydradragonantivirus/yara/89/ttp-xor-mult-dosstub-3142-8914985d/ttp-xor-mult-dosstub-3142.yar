rule TTP_XOR_MULT_DOSStub_3142 {
  strings:
    $key_3142 = { 65 2a [2] 11 32 [2] 56 30 [2] 11 21 [2] 5f 2d [2] 53 27 [2] 44 2c [2] 5f 62 [2] 62 }

  condition:
    any of them
}