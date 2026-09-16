rule TTP_XOR_MULT_DOSStub_fa54 {
  strings:
    $key_fa54 = { ae 3c [2] da 24 [2] 9d 26 [2] da 37 [2] 94 3b [2] 98 31 [2] 8f 3a [2] 94 74 [2] a9 }

  condition:
    any of them
}