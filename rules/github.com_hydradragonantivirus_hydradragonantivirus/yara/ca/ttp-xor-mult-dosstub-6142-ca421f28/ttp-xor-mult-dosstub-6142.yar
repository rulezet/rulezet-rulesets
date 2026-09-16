rule TTP_XOR_MULT_DOSStub_6142 {
  strings:
    $key_6142 = { 35 2a [2] 41 32 [2] 06 30 [2] 41 21 [2] 0f 2d [2] 03 27 [2] 14 2c [2] 0f 62 [2] 32 }

  condition:
    any of them
}