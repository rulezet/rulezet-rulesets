rule TTP_XOR_MULT_DOSStub_fa44 {
  strings:
    $key_fa44 = { ae 2c [2] da 34 [2] 9d 36 [2] da 27 [2] 94 2b [2] 98 21 [2] 8f 2a [2] 94 64 [2] a9 }

  condition:
    any of them
}