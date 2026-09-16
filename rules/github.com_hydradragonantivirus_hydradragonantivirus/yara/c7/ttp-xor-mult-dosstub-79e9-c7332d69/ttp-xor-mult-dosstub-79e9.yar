rule TTP_XOR_MULT_DOSStub_79e9 {
  strings:
    $key_79e9 = { 2d 81 [2] 59 99 [2] 1e 9b [2] 59 8a [2] 17 86 [2] 1b 8c [2] 0c 87 [2] 17 c9 [2] 2a }

  condition:
    any of them
}