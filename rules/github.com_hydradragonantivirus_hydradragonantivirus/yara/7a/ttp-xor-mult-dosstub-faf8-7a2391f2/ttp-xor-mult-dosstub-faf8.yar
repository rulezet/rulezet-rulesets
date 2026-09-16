rule TTP_XOR_MULT_DOSStub_faf8 {
  strings:
    $key_faf8 = { ae 90 [2] da 88 [2] 9d 8a [2] da 9b [2] 94 97 [2] 98 9d [2] 8f 96 [2] 94 d8 [2] a9 }

  condition:
    any of them
}