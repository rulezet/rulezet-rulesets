rule TTP_XOR_MULT_DOSStub_fa66 {
  strings:
    $key_fa66 = { ae 0e [2] da 16 [2] 9d 14 [2] da 05 [2] 94 09 [2] 98 03 [2] 8f 08 [2] 94 46 [2] a9 }

  condition:
    any of them
}