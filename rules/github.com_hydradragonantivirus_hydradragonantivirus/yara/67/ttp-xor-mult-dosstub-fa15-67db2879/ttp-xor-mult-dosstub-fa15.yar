rule TTP_XOR_MULT_DOSStub_fa15 {
  strings:
    $key_fa15 = { ae 7d [2] da 65 [2] 9d 67 [2] da 76 [2] 94 7a [2] 98 70 [2] 8f 7b [2] 94 35 [2] a9 }

  condition:
    any of them
}