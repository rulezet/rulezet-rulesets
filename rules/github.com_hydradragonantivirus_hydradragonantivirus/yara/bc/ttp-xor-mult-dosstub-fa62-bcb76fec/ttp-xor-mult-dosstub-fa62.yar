rule TTP_XOR_MULT_DOSStub_fa62 {
  strings:
    $key_fa62 = { ae 0a [2] da 12 [2] 9d 10 [2] da 01 [2] 94 0d [2] 98 07 [2] 8f 0c [2] 94 42 [2] a9 }

  condition:
    any of them
}