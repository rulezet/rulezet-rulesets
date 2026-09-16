rule TTP_XOR_MULT_DOSStub_fae2 {
  strings:
    $key_fae2 = { ae 8a [2] da 92 [2] 9d 90 [2] da 81 [2] 94 8d [2] 98 87 [2] 8f 8c [2] 94 c2 [2] a9 }

  condition:
    any of them
}