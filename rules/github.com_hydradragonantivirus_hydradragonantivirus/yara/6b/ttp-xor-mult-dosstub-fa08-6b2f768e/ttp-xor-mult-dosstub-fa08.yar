rule TTP_XOR_MULT_DOSStub_fa08 {
  strings:
    $key_fa08 = { ae 60 [2] da 78 [2] 9d 7a [2] da 6b [2] 94 67 [2] 98 6d [2] 8f 66 [2] 94 28 [2] a9 }

  condition:
    any of them
}