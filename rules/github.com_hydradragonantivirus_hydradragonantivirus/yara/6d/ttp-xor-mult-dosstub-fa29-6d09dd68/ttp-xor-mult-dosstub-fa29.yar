rule TTP_XOR_MULT_DOSStub_fa29 {
  strings:
    $key_fa29 = { ae 41 [2] da 59 [2] 9d 5b [2] da 4a [2] 94 46 [2] 98 4c [2] 8f 47 [2] 94 09 [2] a9 }

  condition:
    any of them
}