rule TTP_XOR_MULT_DOSStub_5f42 {
  strings:
    $key_5f42 = { 0b 2a [2] 7f 32 [2] 38 30 [2] 7f 21 [2] 31 2d [2] 3d 27 [2] 2a 2c [2] 31 62 [2] 0c }

  condition:
    any of them
}