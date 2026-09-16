rule TTP_XOR_MULT_DOSStub_fa79 {
  strings:
    $key_fa79 = { ae 11 [2] da 09 [2] 9d 0b [2] da 1a [2] 94 16 [2] 98 1c [2] 8f 17 [2] 94 59 [2] a9 }

  condition:
    any of them
}