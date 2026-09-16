rule TTP_XOR_MULT_DOSStub_fa13 {
  strings:
    $key_fa13 = { ae 7b [2] da 63 [2] 9d 61 [2] da 70 [2] 94 7c [2] 98 76 [2] 8f 7d [2] 94 33 [2] a9 }

  condition:
    any of them
}