rule TTP_XOR_MULT_DOSStub_54f0 {
  strings:
    $key_54f0 = { 00 98 [2] 74 80 [2] 33 82 [2] 74 93 [2] 3a 9f [2] 36 95 [2] 21 9e [2] 3a d0 [2] 07 }

  condition:
    any of them
}