rule TTP_XOR_MULT_DOSStub_fae5 {
  strings:
    $key_fae5 = { ae 8d [2] da 95 [2] 9d 97 [2] da 86 [2] 94 8a [2] 98 80 [2] 8f 8b [2] 94 c5 [2] a9 }

  condition:
    any of them
}