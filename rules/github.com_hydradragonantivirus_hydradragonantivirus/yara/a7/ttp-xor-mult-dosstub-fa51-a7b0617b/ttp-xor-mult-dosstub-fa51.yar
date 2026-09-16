rule TTP_XOR_MULT_DOSStub_fa51 {
  strings:
    $key_fa51 = { ae 39 [2] da 21 [2] 9d 23 [2] da 32 [2] 94 3e [2] 98 34 [2] 8f 3f [2] 94 71 [2] a9 }

  condition:
    any of them
}