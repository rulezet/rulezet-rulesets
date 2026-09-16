rule TTP_XOR_MULT_DOSStub_fa42 {
  strings:
    $key_fa42 = { ae 2a [2] da 32 [2] 9d 30 [2] da 21 [2] 94 2d [2] 98 27 [2] 8f 2c [2] 94 62 [2] a9 }

  condition:
    any of them
}