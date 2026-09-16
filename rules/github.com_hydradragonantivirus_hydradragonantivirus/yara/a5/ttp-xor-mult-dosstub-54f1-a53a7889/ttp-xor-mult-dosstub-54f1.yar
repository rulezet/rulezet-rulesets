rule TTP_XOR_MULT_DOSStub_54f1 {
  strings:
    $key_54f1 = { 00 99 [2] 74 81 [2] 33 83 [2] 74 92 [2] 3a 9e [2] 36 94 [2] 21 9f [2] 3a d1 [2] 07 }

  condition:
    any of them
}