rule TTP_XOR_MULT_DOSStub_58f9 {
  strings:
    $key_58f9 = { 0c 91 [2] 78 89 [2] 3f 8b [2] 78 9a [2] 36 96 [2] 3a 9c [2] 2d 97 [2] 36 d9 [2] 0b }

  condition:
    any of them
}