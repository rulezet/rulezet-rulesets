rule TTP_XOR_MULT_DOSStub_fae4 {
  strings:
    $key_fae4 = { ae 8c [2] da 94 [2] 9d 96 [2] da 87 [2] 94 8b [2] 98 81 [2] 8f 8a [2] 94 c4 [2] a9 }

  condition:
    any of them
}