rule TTP_XOR_MULT_DOSStub_fa02 {
  strings:
    $key_fa02 = { ae 6a [2] da 72 [2] 9d 70 [2] da 61 [2] 94 6d [2] 98 67 [2] 8f 6c [2] 94 22 [2] a9 }

  condition:
    any of them
}