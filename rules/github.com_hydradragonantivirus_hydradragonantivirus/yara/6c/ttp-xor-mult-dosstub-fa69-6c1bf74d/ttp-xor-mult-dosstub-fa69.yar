rule TTP_XOR_MULT_DOSStub_fa69 {
  strings:
    $key_fa69 = { ae 01 [2] da 19 [2] 9d 1b [2] da 0a [2] 94 06 [2] 98 0c [2] 8f 07 [2] 94 49 [2] a9 }

  condition:
    any of them
}