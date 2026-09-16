rule TTP_XOR_MULT_DOSStub_fa70 {
  strings:
    $key_fa70 = { ae 18 [2] da 00 [2] 9d 02 [2] da 13 [2] 94 1f [2] 98 15 [2] 8f 1e [2] 94 50 [2] a9 }

  condition:
    any of them
}