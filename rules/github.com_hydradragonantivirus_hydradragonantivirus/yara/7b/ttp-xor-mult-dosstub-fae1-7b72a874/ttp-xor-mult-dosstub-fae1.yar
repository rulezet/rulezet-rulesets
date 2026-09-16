rule TTP_XOR_MULT_DOSStub_fae1 {
  strings:
    $key_fae1 = { ae 89 [2] da 91 [2] 9d 93 [2] da 82 [2] 94 8e [2] 98 84 [2] 8f 8f [2] 94 c1 [2] a9 }

  condition:
    any of them
}