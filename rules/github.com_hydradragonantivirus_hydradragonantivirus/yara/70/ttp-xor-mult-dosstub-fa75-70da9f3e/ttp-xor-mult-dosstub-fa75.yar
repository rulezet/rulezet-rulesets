rule TTP_XOR_MULT_DOSStub_fa75 {
  strings:
    $key_fa75 = { ae 1d [2] da 05 [2] 9d 07 [2] da 16 [2] 94 1a [2] 98 10 [2] 8f 1b [2] 94 55 [2] a9 }

  condition:
    any of them
}