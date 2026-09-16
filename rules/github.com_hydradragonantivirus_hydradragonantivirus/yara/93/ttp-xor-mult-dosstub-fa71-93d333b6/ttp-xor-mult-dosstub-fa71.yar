rule TTP_XOR_MULT_DOSStub_fa71 {
  strings:
    $key_fa71 = { ae 19 [2] da 01 [2] 9d 03 [2] da 12 [2] 94 1e [2] 98 14 [2] 8f 1f [2] 94 51 [2] a9 }

  condition:
    any of them
}