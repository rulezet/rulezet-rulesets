rule TTP_XOR_MULT_DOSStub_58e7 {
  strings:
    $key_58e7 = { 0c 8f [2] 78 97 [2] 3f 95 [2] 78 84 [2] 36 88 [2] 3a 82 [2] 2d 89 [2] 36 c7 [2] 0b }

  condition:
    any of them
}