rule TTP_XOR_MULT_DOSStub_1f42 {
  strings:
    $key_1f42 = { 4b 2a [2] 3f 32 [2] 78 30 [2] 3f 21 [2] 71 2d [2] 7d 27 [2] 6a 2c [2] 71 62 [2] 4c }

  condition:
    any of them
}