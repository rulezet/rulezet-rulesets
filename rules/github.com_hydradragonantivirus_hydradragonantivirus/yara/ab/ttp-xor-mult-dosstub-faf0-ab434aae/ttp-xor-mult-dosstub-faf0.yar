rule TTP_XOR_MULT_DOSStub_faf0 {
  strings:
    $key_faf0 = { ae 98 [2] da 80 [2] 9d 82 [2] da 93 [2] 94 9f [2] 98 95 [2] 8f 9e [2] 94 d0 [2] a9 }

  condition:
    any of them
}