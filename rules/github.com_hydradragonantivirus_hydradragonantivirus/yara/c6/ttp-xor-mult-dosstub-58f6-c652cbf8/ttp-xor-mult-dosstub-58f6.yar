rule TTP_XOR_MULT_DOSStub_58f6 {
  strings:
    $key_58f6 = { 0c 9e [2] 78 86 [2] 3f 84 [2] 78 95 [2] 36 99 [2] 3a 93 [2] 2d 98 [2] 36 d6 [2] 0b }

  condition:
    any of them
}