rule TTP_XOR_MULT_DOSStub_fa50 {
  strings:
    $key_fa50 = { ae 38 [2] da 20 [2] 9d 22 [2] da 33 [2] 94 3f [2] 98 35 [2] 8f 3e [2] 94 70 [2] a9 }

  condition:
    any of them
}