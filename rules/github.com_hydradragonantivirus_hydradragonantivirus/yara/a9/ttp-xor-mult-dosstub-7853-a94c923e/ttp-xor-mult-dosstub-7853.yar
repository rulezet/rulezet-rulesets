rule TTP_XOR_MULT_DOSStub_7853 {
  strings:
    $key_7853 = { 2c 3b [2] 58 23 [2] 1f 21 [2] 58 30 [2] 16 3c [2] 1a 36 [2] 0d 3d [2] 16 73 [2] 2b }

  condition:
    any of them
}