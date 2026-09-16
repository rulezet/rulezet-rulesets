rule TTP_XOR_MULT_DOSStub_fa56 {
  strings:
    $key_fa56 = { ae 3e [2] da 26 [2] 9d 24 [2] da 35 [2] 94 39 [2] 98 33 [2] 8f 38 [2] 94 76 [2] a9 }

  condition:
    any of them
}