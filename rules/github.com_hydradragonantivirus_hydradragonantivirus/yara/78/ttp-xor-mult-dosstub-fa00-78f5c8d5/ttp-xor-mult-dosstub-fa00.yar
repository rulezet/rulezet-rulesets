rule TTP_XOR_MULT_DOSStub_fa00 {
  strings:
    $key_fa00 = { ae 68 [2] da 70 [2] 9d 72 [2] da 63 [2] 94 6f [2] 98 65 [2] 8f 6e [2] 94 20 [2] a9 }

  condition:
    any of them
}