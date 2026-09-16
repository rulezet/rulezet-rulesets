rule TTP_XOR_MULT_DOSStub_fae0 {
  strings:
    $key_fae0 = { ae 88 [2] da 90 [2] 9d 92 [2] da 83 [2] 94 8f [2] 98 85 [2] 8f 8e [2] 94 c0 [2] a9 }

  condition:
    any of them
}