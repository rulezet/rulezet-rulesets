rule TTP_XOR_MULT_DOSStub_5864 {
  strings:
    $key_5864 = { 0c 0c [2] 78 14 [2] 3f 16 [2] 78 07 [2] 36 0b [2] 3a 01 [2] 2d 0a [2] 36 44 [2] 0b }

  condition:
    any of them
}