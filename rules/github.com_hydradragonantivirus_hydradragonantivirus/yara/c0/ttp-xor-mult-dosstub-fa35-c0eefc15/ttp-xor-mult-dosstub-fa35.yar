rule TTP_XOR_MULT_DOSStub_fa35 {
  strings:
    $key_fa35 = { ae 5d [2] da 45 [2] 9d 47 [2] da 56 [2] 94 5a [2] 98 50 [2] 8f 5b [2] 94 15 [2] a9 }

  condition:
    any of them
}