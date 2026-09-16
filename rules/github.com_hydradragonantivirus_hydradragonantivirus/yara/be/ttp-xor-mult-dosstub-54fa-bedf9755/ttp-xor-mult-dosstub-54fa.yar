rule TTP_XOR_MULT_DOSStub_54fa {
  strings:
    $key_54fa = { 00 92 [2] 74 8a [2] 33 88 [2] 74 99 [2] 3a 95 [2] 36 9f [2] 21 94 [2] 3a da [2] 07 }

  condition:
    any of them
}