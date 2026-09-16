rule TTP_XOR_MULT_DOSStub_fa7b {
  strings:
    $key_fa7b = { ae 13 [2] da 0b [2] 9d 09 [2] da 18 [2] 94 14 [2] 98 1e [2] 8f 15 [2] 94 5b [2] a9 }

  condition:
    any of them
}