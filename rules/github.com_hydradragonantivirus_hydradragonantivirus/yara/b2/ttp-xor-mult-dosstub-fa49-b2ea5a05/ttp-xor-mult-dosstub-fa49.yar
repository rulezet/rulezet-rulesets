rule TTP_XOR_MULT_DOSStub_fa49 {
  strings:
    $key_fa49 = { ae 21 [2] da 39 [2] 9d 3b [2] da 2a [2] 94 26 [2] 98 2c [2] 8f 27 [2] 94 69 [2] a9 }

  condition:
    any of them
}