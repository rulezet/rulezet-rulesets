rule TTP_XOR_MULT_DOSStub_fa65 {
  strings:
    $key_fa65 = { ae 0d [2] da 15 [2] 9d 17 [2] da 06 [2] 94 0a [2] 98 00 [2] 8f 0b [2] 94 45 [2] a9 }

  condition:
    any of them
}