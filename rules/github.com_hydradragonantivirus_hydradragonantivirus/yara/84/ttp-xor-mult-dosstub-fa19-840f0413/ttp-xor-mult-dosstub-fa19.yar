rule TTP_XOR_MULT_DOSStub_fa19 {
  strings:
    $key_fa19 = { ae 71 [2] da 69 [2] 9d 6b [2] da 7a [2] 94 76 [2] 98 7c [2] 8f 77 [2] 94 39 [2] a9 }

  condition:
    any of them
}