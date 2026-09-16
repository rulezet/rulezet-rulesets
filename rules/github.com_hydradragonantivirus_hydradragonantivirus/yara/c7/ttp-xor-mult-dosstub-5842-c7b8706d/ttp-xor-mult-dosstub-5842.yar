rule TTP_XOR_MULT_DOSStub_5842 {
  strings:
    $key_5842 = { 0c 2a [2] 78 32 [2] 3f 30 [2] 78 21 [2] 36 2d [2] 3a 27 [2] 2d 2c [2] 36 62 [2] 0b }

  condition:
    any of them
}