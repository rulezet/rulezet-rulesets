rule TTP_XOR_MULT_DOSStub_5869 {
  strings:
    $key_5869 = { 0c 01 [2] 78 19 [2] 3f 1b [2] 78 0a [2] 36 06 [2] 3a 0c [2] 2d 07 [2] 36 49 [2] 0b }

  condition:
    any of them
}