rule TTP_XOR_MULT_DOSStub_58f2 {
  strings:
    $key_58f2 = { 0c 9a [2] 78 82 [2] 3f 80 [2] 78 91 [2] 36 9d [2] 3a 97 [2] 2d 9c [2] 36 d2 [2] 0b }

  condition:
    any of them
}