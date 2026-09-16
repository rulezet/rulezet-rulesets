rule TTP_XOR_MULT_DOSStub_4fe9 {
  strings:
    $key_4fe9 = { 1b 81 [2] 6f 99 [2] 28 9b [2] 6f 8a [2] 21 86 [2] 2d 8c [2] 3a 87 [2] 21 c9 [2] 1c }

  condition:
    any of them
}