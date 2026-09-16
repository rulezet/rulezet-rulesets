rule TTP_XOR_MULT_DOSStub_58f8 {
  strings:
    $key_58f8 = { 0c 90 [2] 78 88 [2] 3f 8a [2] 78 9b [2] 36 97 [2] 3a 9d [2] 2d 96 [2] 36 d8 [2] 0b }

  condition:
    any of them
}