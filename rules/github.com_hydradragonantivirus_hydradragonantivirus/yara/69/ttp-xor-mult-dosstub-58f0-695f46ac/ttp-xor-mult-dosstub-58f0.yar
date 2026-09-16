rule TTP_XOR_MULT_DOSStub_58f0 {
  strings:
    $key_58f0 = { 0c 98 [2] 78 80 [2] 3f 82 [2] 78 93 [2] 36 9f [2] 3a 95 [2] 2d 9e [2] 36 d0 [2] 0b }

  condition:
    any of them
}