rule TTP_XOR_MULT_DOSStub_4ae9 {
  strings:
    $key_4ae9 = { 1e 81 [2] 6a 99 [2] 2d 9b [2] 6a 8a [2] 24 86 [2] 28 8c [2] 3f 87 [2] 24 c9 [2] 19 }

  condition:
    any of them
}