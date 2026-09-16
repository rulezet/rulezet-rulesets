rule TTP_XOR_MULT_DOSStub_58e9 {
  strings:
    $key_58e9 = { 0c 81 [2] 78 99 [2] 3f 9b [2] 78 8a [2] 36 86 [2] 3a 8c [2] 2d 87 [2] 36 c9 [2] 0b }

  condition:
    any of them
}