rule TTP_XOR_MULT_DOSStub_fa09 {
  strings:
    $key_fa09 = { ae 61 [2] da 79 [2] 9d 7b [2] da 6a [2] 94 66 [2] 98 6c [2] 8f 67 [2] 94 29 [2] a9 }

  condition:
    any of them
}