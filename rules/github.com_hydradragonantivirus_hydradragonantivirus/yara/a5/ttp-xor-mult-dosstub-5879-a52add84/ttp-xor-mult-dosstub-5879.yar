rule TTP_XOR_MULT_DOSStub_5879 {
  strings:
    $key_5879 = { 0c 11 [2] 78 09 [2] 3f 0b [2] 78 1a [2] 36 16 [2] 3a 1c [2] 2d 17 [2] 36 59 [2] 0b }

  condition:
    any of them
}