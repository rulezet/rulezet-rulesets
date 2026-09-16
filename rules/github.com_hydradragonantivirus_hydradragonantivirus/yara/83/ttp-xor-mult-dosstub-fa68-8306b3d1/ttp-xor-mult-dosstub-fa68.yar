rule TTP_XOR_MULT_DOSStub_fa68 {
  strings:
    $key_fa68 = { ae 00 [2] da 18 [2] 9d 1a [2] da 0b [2] 94 07 [2] 98 0d [2] 8f 06 [2] 94 48 [2] a9 }

  condition:
    any of them
}