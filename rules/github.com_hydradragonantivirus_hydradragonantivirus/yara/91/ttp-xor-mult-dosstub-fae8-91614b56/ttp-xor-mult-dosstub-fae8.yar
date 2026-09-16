rule TTP_XOR_MULT_DOSStub_fae8 {
  strings:
    $key_fae8 = { ae 80 [2] da 98 [2] 9d 9a [2] da 8b [2] 94 87 [2] 98 8d [2] 8f 86 [2] 94 c8 [2] a9 }

  condition:
    any of them
}