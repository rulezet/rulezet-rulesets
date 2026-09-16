rule TTP_XOR_MULT_DOSStub_3842 {
  strings:
    $key_3842 = { 6c 2a [2] 18 32 [2] 5f 30 [2] 18 21 [2] 56 2d [2] 5a 27 [2] 4d 2c [2] 56 62 [2] 6b }

  condition:
    any of them
}